# fishhook 

```
__fishhook__ is a very simple library that enables dynamically rebinding symbols in Mach-O binaries running on iOS in the simulator and on device. This provides functionality that is similar to using [`DYLD_INTERPOSE`][interpose] on OS X. At Facebook, we've found it useful as a way to hook calls in libSystem for debugging/tracing purposes (for example, auditing(审查) for double-close (欺骗) issues with file descriptors (文件描述符)).
```

**功能**: (`dyld interpose`) 针对**动态库** 来 `hook` `c` 函数的库. ps: 安卓可以查看 **FastHook**
**不试用**: 静态库的函数 `hook`
**问题**: 如果将来苹果更新动态链接器为 `dyld 3.0`, 那么该库会失效, 详情查看 [fishhook with dyld 3.0 ](https://github.com/facebook/fishhook/issues/43)

有关动态库插入的文档, 苹果官方的动态库插入宏 [DYLD_INTERPOSE](https://opensource.apple.com/source/dyld/dyld-210.2.3/include/mach-o/dyld-interposing.h)

```
#if !defined(_DYLD_INTERPOSING_H_)
#define _DYLD_INTERPOSING_H_

/*
 *  Example:
 *
 *  static
 *  int
 *  my_open(const char* path, int flags, mode_t mode)
 *  {
 *    int value;
 *    // do stuff before open (including changing the arguments)
 *    value = open(path, flags, mode);
 *    // do stuff after open (including changing the return value(s))
 *    return value;
 *  }
 *  DYLD_INTERPOSE(my_open, open)
 */

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

#endif
```

`fishhook` 文档中的查找过程

![](media/15752787257779/15752810800353.jpg)

步骤一: 
1. 查找 记录 `__LINKEDIT` / `LC_SYMTAB` / `LC_DYSYMTAB` 相关的3 个 `Command` 
2. 根据 `__LINKEDIT` 和 `LC_SYMTAB` / `LC_DYSYMTAB` 计算出 字符串表,符号表和 动态符号表(间接符号表)共3个位置
3. 因为我们真正的函数映射表 `__nl_symbol_ptr` 和 `__la_symbol_ptr` 在 `__DATA` 段存在, 因为无法直接找到,所以我们需要遍历所有的 `section` , 根据 `section` 中 的 `flags` 字段, 来确定其是否是 `__nl_symbol_ptr` 或者 `__la_symbol_ptr`, 如果找到将会对其进行解析.

步骤二:

- 处理 `__la_symbol_ptr`或者`__nl_symbol_ptr`
- 遍历 `indirect_symbol` 表中 归属 `__la_symbol_ptr`或者`__nl_symbol_ptr` 那部分数组信息, 然后根据这部分数组的元素获取 符号表 元素 `nlist` 的索引
- `Symbol Table` -> 元素 `struct nlist` 包含以下内容, 根据其中的 `n_strx` 获取 字符串表 该符号的偏移量
    1. String Table Offset
    2. Section Number
    3. Type
    4. Additional Info
    5. Value
- `String Table` 定位其 `offset`  定位符号, 如果与想要替换的符号相同的话, 则 更新 `Indirect Symbol Table` 对应符号的 间接地址
        1. `indirect_symbol_bindings[i] = cur->rebindings[j].replacement;`


## Mach-O 

Mac中的可执行文件分类如下:

- Mach-O 格式 [MachOOverview](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html)
- 通用二进制格式 
    - 其是为了解决多架构的问题, 也称为 胖二进制格式, 它包含多个 `Mach-O` 文件
    - FAT_MAGIC: 0xcafebabe
- 解释器脚本格式

查看格式类型可以使用 其二进制中的 `Magic`  数字

真正要了解的是 `Mach-O` 格式, 可以使用 `MachOView` 软件

![](media/15752787257779/15752835954304.jpg)
如下组成: 
- Mach Header
- Load Commands
    - 描述了文件中数据的具体组织结构，不同的数据类型使用不同的加载命令表示
    - 不同的动态库有不同的加载指令
    - 不同的command 有不同的长度
- Multi-Sections
- Symbol Table
- String Table
- ... 

之所以按照 Segment -> Section 的结构组织方式，是因为在同一个 Segment 下的 Section，可以控制相同的权限，也可以不完全按照 Page 的大小进行内存对其，节省内存的空间

**magic**: 用于标识当前设备的是大端序还是小端序。如果是0xfeedfacf(MH_MAGIC_64)就是大端序，而0xcffaedfe(MH_CIGAM_64)是小端序，iOS系统上是小端序

也可以用 `Hopper` 查看更详细的信息

![](media/15752787257779/15752849843439.jpg)


## 相关表

```
/**
* 1. rebindings 需要替换的符号记录数组
* 2. section 为 `__la_symbol_ptr` 的section 或者 `__nl_symbol_ptr` 的section
* 3. slide 镜像的基地址偏移量
* 4. symtab 符号表 包含所有的符号信息
* 5. strtab 字符串表 包含所有的符号名称
* 6. indirect_symtab 间接符号表 (包含了动态库加载时的 `__la_symbol_ptr`符号与`__nl_symbol_ptr`符号 got符号 以及其他符号)
*/
static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab)
```

### section

![](media/15752787257779/15758939084290.jpg)

```
struct section_64 { /* for 64-bit architectures */
	char		sectname[16];	/* name of this section */
	char		segname[16];	/* segment this section goes in */
	uint64_t	addr;		/* memory address of this section */
	uint64_t	size;		/* size in bytes of this section */
	uint32_t	offset;		/* file offset of this section */
	uint32_t	align;		/* section alignment (power of 2) */
	uint32_t	reloff;		/* file offset of relocation entries */
	uint32_t	nreloc;		/* number of relocation entries */
	uint32_t	flags;		/* flags (section type and attributes)*/
	uint32_t	reserved1;	/* reserved (for offset or index) */
	uint32_t	reserved2;	/* reserved (for count or sizeof) */
	uint32_t	reserved3;	/* reserved */
};
```

### __nl_symbol_ptr

- 位于 `DATA` 区
- `__nl_symbol_ptr` 非懒加载的符号表, 在**动态库** load 的时候就会将符号与真正的虚拟地址进行映射

### __la_symbol_ptr 


![](media/15752787257779/15759010849520.jpg)

![](media/15752787257779/15759011537689.jpg)


- 位于 `DATA` 区
- `__la_symbol_ptr` 懒加载的符号表,其数据在动态库`load`的时候会被 `bind` 成 `dyld_stub_helper`, 在函数第一次是有的时候,才会将 替换为其真正的地址 !!!
- 懒加载是为了解决类似动态链接下对于全局和静态的数据访问都要进行复杂的GOT定位, 然后间接寻址的问题

### 符号表

符号表: 保存所有符号, 比如 `__la_symbol_ptr`或者 `__nl_symbol_ptr` 中的符号和本地符号等.  ~~其只是对debug有用。strip会去除符号表, 对这句话没有求证~~

```
/*
 * This is the symbol table entry structure for 64-bit architectures.
 */
struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};
```

- 重点: 记录了 符号在 字符串表中的对应偏移量 `n_strx` , 可以定位到符号表中 符号的 全名称

### Dynamic Symbol Table / DST 

```
 An indirect symbol table entry is simply a 32bit index into the symbol tableto the symbol that the pointer or stub is refering to.  Unless it is for a non-lazy symbol pointer section for a defined symbol which strip(1) as removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
```

Dynamic Symbol Table 动态符号(间接符号表)表: 
- 间接符号表中的 **元素** 是一个 `uint32_t` 32位大小的偏移量值，指针的值是对应条目 `n_list` 在符号表中的位置. 
- 保存与动态链接相关的导入导出符号， 比如 `__la_symbol_ptr`或者 `__nl_symbol_ptr` 的符号信息 (仅仅是对应符号表下标的信息), 不包括模块内部的符号. 
- 该表在 dyld 时期使用，并且在对象被加载的时候映射到进程的地址空间。所以我们可以说 DST 是符号表的子集

### 字符串表 .strtab / string table

![](media/15752787257779/15759020207201.jpg)

摘自[字符串表节](https://docs.oracle.com/cd/E26926_01/html/E25910/chapter6-73709.html)

可执行文件中所有的符号名称或者段名称等信息, 因为字符串的长度不固定, 所以无法用固定的结构表示它, 常见的做法是: 将字符串集中存储到一个表中, 然后使用字符串在表中的偏移来引用字符串. 

> 问题: 如何知道符号表中某个符号的长度, 答符号表存储的字符以 \0 结尾


## 参考

- [深入剖析Macho (1)](http://satanwoo.github.io/2017/06/13/Macho-1/)
- [Mach-O 与动态链接](https://zhangbuhuai.com/post/macho-dynamic-link.html)
- [Mach-O 文件格式探索](https://xiaozhuanlan.com/topic/6750382941)
- [Mach-O 与动态链接](https://zhangbuhuai.com/post/macho-dynamic-link.html#dyld-stub-binder)
- [Hook 原理之 fishhook 源码解析](https://amywushu.github.io/2017/02/27/源码学习-Hook-原理之-fishhook-源码解析.html)