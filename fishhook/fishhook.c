// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

// 定义 mach 头, 命令结构体, Section结构体等, 根据不同的CPU

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct rebindings_entry
{
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel)
{
  struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
  if (!new_entry)
  {
    return -1;
  }
  new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings)
  {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}

/**
 * 查询该Section的读写权限
 * 
*/
static vm_prot_t get_protection(void *sectionStart)
{
  mach_port_t task = mach_task_self();
  vm_size_t size = 0;
  vm_address_t address = (vm_address_t)sectionStart;
  memory_object_name_t object;
#if __LP64__
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  vm_region_basic_info_data_64_t info;
  kern_return_t info_ret = vm_region_64(
      task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
  vm_region_basic_info_data_t info;
  kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
  if (info_ret == KERN_SUCCESS)
  {
    return info.protection;
  }
  else
  {
    return VM_PROT_READ;
  }
}

// 绑定该部分 section的符号
// 具体的验证学习,可以查看 https://xiaozhuanlan.com/topic/0956137284
// 真正函数调用的时候是从 动态符号表(间接符号) 中查找符号的 间接符号地址调用的
// 1. 我们遍历 sectiond 的符号
// 2. 根据符号找到其对应的间接符号表中的位置
// 3. 根据间接符号表 -> 定位符号表 中 对应下标的  nlist_64 结构体
// 4. 根据 nlist_64 对应的 值 找到 字符串表对应位置的符号
// 5. 比较该符号是否与需要hook的符号一致
// 6. 一致,则更新 间接符号表的 函数地址
static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab)
{
  // 判断是否是 `__DATA` 常量区
  const bool isDataConst = strcmp(section->segname, "__DATA_CONST") == 0;
  // indirect_symtab 动态符号表地址
  // reserved1 保留字段 , 表示  reserved (for offset or index)
  //  indirect_symbol_indices = 动态符号表 + 偏移量
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  //  indirect_symbol_bindings 动态符号边的 = slide(基础偏移地址) + Section的内存相对地址 (memory address of this section)
  //  已知其 value 是一个指针类型，整段区域用二阶指针来获取
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);

  // 可读
  vm_prot_t oldProtection = VM_PROT_READ;
  if (isDataConst)
  {
    // 如果是常量区,查询权限
    oldProtection = get_protection(rebindings);
    // 让section可读写, 便于我们修改函数地址等数据
    mprotect(indirect_symbol_bindings, section->size, PROT_READ | PROT_WRITE);
  }
  // 偏移的时候 使用 `size / sizeof(void *)` 为一个单位
  for (uint i = 0; i < section->size / sizeof(void *); i++)
  {
    // 查看该下标下的间接符号信息
    uint32_t symtab_index = indirect_symbol_indices[i];

    /*
    * An indirect symbol table entry is simply a 32bit index into the symbol table 
    * to the symbol that the pointer or stub is refering to.  Unless it is for a
    * non-lazy symbol pointer section for a defined symbol which strip(1) as 
    * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
    * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
    */
    // 如果是 abs 或者 是 本地 则跳过
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS))
    {
      continue;
    }
    //  该下标符号表元素是 nlist_64 结构, 查找里面的 index into the string table ,也就是 n_strx
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    // 获取符号名称
    char *symbol_name = strtab + strtab_offset;
    // 符号长度 ??? 做什么用, 是因为符号很多是以 `_` 开头吗
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
    // 遍历所有的hook符号链表
    struct rebindings_entry *cur = rebindings;
    while (cur)
    {
      for (uint j = 0; j < cur->rebindings_nel; j++)
      {
        // 当前符号是否和需要hook的原函数名称一致
        if (symbol_name_longer_than_1 &&
            strcmp(&symbol_name[1], cur->rebindings[j].name) == 0)
        {
          // 如果被hook函数存在且动态符号表中的函数地址不等于 新的hook函数, 则将hook函数链表中的原函数地址记录下来 (动态函数表的函数地址)
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement)
          {
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }
          // 并且将hook函数地址 更新到 动态函数表中
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto symbol_loop; // 结束该内层的遍历, 查找下一个符号
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
  // 做什么的
  if (isDataConst)
  {
    int protection = 0;
    if (oldProtection & VM_PROT_READ)
    {
      protection |= PROT_READ;
    }
    if (oldProtection & VM_PROT_WRITE)
    {
      protection |= PROT_WRITE;
    }
    if (oldProtection & VM_PROT_EXECUTE)
    {
      protection |= PROT_EXEC;
    }
    mprotect(indirect_symbol_bindings, section->size, protection);
  }
}

/**
 * 重新绑定符号的过程
 * rebindings 所有的hook替换方法链表
 * header mach-o 文件头
 * slide 基础偏移地址
 * 
*/
static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide)
{
  Dl_info info;
  if (dladdr(header, &info) == 0)
  {
    return;
  }

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command *symtab_cmd = NULL;
  struct dysymtab_command *dysymtab_cmd = NULL;

  /**
   * 
   * LC_SYMTAB这个LoadCommand主要提供了两个信息
	 * Symbol Table的偏移量与Symbol Table中元素的个数
	 * String Table的偏移量与String Table的长度
   * LC_DYSYMTAB
	 * 提供了动态符号表的位移和元素个数，还有一些其他的表格索引
   * LC_SEGMENT.__LINKEDIT
	 * 含有为动态链接库使用的原始数据
   * 
  */

  // 首个命令的地址,也就是header的结束地址
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  // 根据命令的大小做偏移, 某个命令的大小都不同
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
  {
    // 取出 load command
    cur_seg_cmd = (segment_command_t *)cur;
    // 如果是 segment 的宏定义
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT)
    {
      // 如果segment 名字是 `__LINKEDIT` 的话, 含有为动态链接库使用的原始数据, ，如符号，字符串和重定位的表的入口
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0)
      {
        linkedit_segment = cur_seg_cmd;
      }
    }
    // link-edit stab symbol table info
    // Symbol Table的偏移量与Symbol Table中元素的个数
    // String Table的偏移量与String Table的长度
    else if (cur_seg_cmd->cmd == LC_SYMTAB)
    {
      symtab_cmd = (struct symtab_command *)cur_seg_cmd;
    }
    // 提供了dynamic symbol table 动态符号表的位移和元素个数，还有一些其他的表格索引
    else if (cur_seg_cmd->cmd == LC_DYSYMTAB)
    {
      dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms)
  {
    return;
  }

  // 基址 = __LINKEDIT.VM_Address - __LINK.File_Offset + silde的改变值
  // Find base symbol/string table addresses 确定基地址
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  // 确定符号表的地址 = 基地址 + 符号表的偏移量, 其余的表基本也是如此计算
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  // 确定字符串表的地址
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // 确定动态符号表的地址
  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  // mach-O header的结束地址
  cur = (uintptr_t)header + sizeof(mach_header_t);
  // 遍历所有的command
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
  {
    // 获取 load command
    cur_seg_cmd = (segment_command_t *)cur;
    // 是否是 segment
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT)
    {
      // 如果不是 `__DATA` 段 且不是 `__DATA`的常量区, 则继续
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0)
      {
        continue;
      }
      // 遍历 segment, cur_seg_cmd->nsects: 此segment的 section 数量
      for (uint j = 0; j < cur_seg_cmd->nsects; j++)
      {
        //获取当前的Section
        section_t *sect =
            (section_t *)(cur + sizeof(segment_command_t)) + j;
        // 查询 Section的类型, 如果是 `__la_symbol_ptr` 类型的. 绑定该部分
        // 该部分符号会在该符号被第一次调用时，通过 dyld 中的 dyld_stub_binder 过程来进行加载
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS)
        {
          // 则执行真正绑定过程
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
        // 查询 Section的类型, 如果是 `__nl_symbol_ptr` 类型的. 绑定该部分
        // non-lazy 符号是在动态链接库绑定的时候进行加载的
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS)
        {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}

// 动态库加载时 中转的函数, 因为要复合回调函数的结构
// intptr_t 为不同平台的指针地址存储类型, 比如64位 8字节, long int 单位长度, 32字节 int 单位长度
static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide)
{
  // 真正的调用
  rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel)
{
  struct rebindings_entry *rebindings_head = NULL;
  int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
  rebind_symbols_for_image(rebindings_head, (const struct mach_header *)header, slide);
  if (rebindings_head)
  {
    free(rebindings_head->rebindings);
  }
  free(rebindings_head);
  return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel)
{
  // 分配hook链表的空间
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0)
  {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
  // 首次的话 添加动态库的加载回调函数
  if (!_rebindings_head->next)
  {
    // it is called as each new image is loaded and bound (but initializers not yet run) 动态库被加载或者链接的时候
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  }
  else
  {
    // 否则直接执行回调函数的处理, 处理已经载入的镜像
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++)
    {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
