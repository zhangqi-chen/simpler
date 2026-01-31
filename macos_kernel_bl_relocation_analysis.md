# macOS ARM64 内核 BL 指令重定位问题分析

## 问题现象

在 macOS ARM64 上运行 `python examples/host_build_graph_sim_example/main.py` 时卡死，而在 Ubuntu 上正常执行。

## 根本原因

### 1. BL 指令跳转的函数是什么？

跳转目标是 `TLoad` 模板函数的实例化版本（带 `constprop.0` 后缀，表示编译器做了常量传播优化）：

```
__ZN3pto5TLoadINS_4TileILNS_8TileTypeE0EfLi128ELi128E...constprop.0
```

Demangled: `pto::TLoad<pto::Tile<...>, pto::GlobalTensor<...>>::constprop.0`

### 2. TLoad 函数在 .text 段内还是外？

**TLoad 函数实际上在 .text 段内部**：

```
符号表:
0000000000000000 T _kernel_add          # 入口函数
0000000000000100 t __ZN3pto5TLoad...    # TLoad 函数

.text 段信息:
  addr: 0x0000000000000000
  size: 0x000000000000014c              # 段大小 = 0x14c
```

TLoad 在地址 0x100，而 .text 段范围是 0x0 ~ 0x14c，所以 **TLoad 在 .text 段内**。

### 3. 为什么 BL 指令不能正确跳转？

**Mach-O 格式的重定位机制问题**：

查看 BL 指令的原始字节（文件偏移 0x300 处）：
```
00000300: 0000 0094    →  0x94000000 (little-endian)
```

ARM64 BL 指令格式：
- bits [31:26] = `100101` (BL opcode)
- bits [25:0] = 偏移量（有符号，乘以4）

`0x94000000` 解码：
- opcode = `100101` ✓
- **offset = 0** ← 问题所在！

偏移量为 0 意味着 BL 会跳转到自己的地址（0x38），而不是 TLoad 的地址（0x100）。

### 4. Mach-O 重定位表

```
Relocation information (__TEXT,__text) 2 entries
address  pcrel  extern  type   symbolnum/value
00000048 True   True    BR26   __ZN3pto5TLoad...constprop.0
00000038 True   True    BR26   __ZN3pto5TLoad...constprop.0
```

Mach-O 格式要求：
- BL 指令的立即数字段设置为 0
- 正确的跳转偏移量记录在重定位表中
- **链接器负责在链接时修正这些偏移量**

### 5. 为什么 Ubuntu 没有这个问题？

两个可能的原因：

#### 原因 A: ELF 格式的重定位策略不同

在 ELF 格式的 .o 文件中，对于**同一 section 内的函数调用**，编译器会直接在 BL/CALL 指令中编码正确的相对偏移量，**不需要重定位**。

| 格式 | BL 指令编码 | 重定位 |
|------|------------|--------|
| Mach-O | offset = 0 | 需要重定位表修正 |
| ELF | offset = 正确值 | 不需要重定位 |

#### 原因 B: x86_64 vs ARM64 的内联差异

在 Ubuntu x86_64 上，编译器可能将 TLoad **完全内联**到 kernel_add 中，根本不生成独立的 TLoad 函数，因此没有 BL/CALL 指令。

ARM64 macOS 上的编译器选择将 TLoad 作为独立函数（做了 constprop 优化但没有完全内联）。

### 6. 为什么 TLoad 没有被内联？

调用链：
```cpp
TLOAD(src0Tile, src0Global)
  → pto::TLOAD(...)           // PTO_INST = always_inline ✓
    → TLOAD_IMPL(...)         // PTO_INTERNAL = always_inline ✓
      → TLoad<...>(...)       // __tf__ AICORE void ← 没有 always_inline！
```

`TLoad` 函数定义（在 TLoad.hpp）：
```cpp
template <typename TileData, typename GlobalData>
__tf__ AICORE void TLoad(...)  // 没有 PTO_INLINE!
```

**TLoad 函数缺少 `always_inline` 属性**，编译器可以选择不内联它。

## 解决方案

### 方案 1: 给 TLoad 添加 always_inline（推荐）

修改 `pto-isa/include/pto/cpu/TLoad.hpp`：

```cpp
// 修改前
template <typename TileData, typename GlobalData>
__tf__ AICORE void TLoad(...)

// 修改后
template <typename TileData, typename GlobalData>
__tf__ AICORE PTO_INLINE void TLoad(...)
```

### 方案 2: 在提取 .text 段后处理重定位

在 elf_parser.py 中添加 Mach-O 重定位处理逻辑，根据重定位表修正 BL 指令的偏移量。

### 方案 3: 编译为共享库而非 .o 文件

将内核编译为 .dylib/.so，共享库会自动处理所有重定位。

## 总结

| 项目 | macOS ARM64 | Ubuntu x86_64 |
|------|-------------|---------------|
| 目标文件格式 | Mach-O | ELF |
| BL 指令偏移 | 0（需重定位） | 直接编码正确值 |
| TLoad 内联 | 否（constprop） | 可能完全内联 |
| 提取 .text 后 | BL 跳转到自己 | 正常工作 |
