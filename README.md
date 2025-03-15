# ReCFA  
Resilient Control-Flow Attestation（弹性控制流认证）

## 需求

- ReCFA 已在 **Ubuntu-18.04.5 LTS 64-bit** 上进行测试  
- 依赖工具 (**请在运行 ReCFA 的 Ubuntu 18.04 主机上部署这些工具，typearmor 除外**)  
  - gcc 7.5.0  
  - llvm 10.0.0  
  - Dyninst 10.1.0  
  - zstandard 1.5.0  
  - typearmor（最新版本）搭配 Dyninst 9.3.1 (**请根据 `ReCFA-dev` 仓库的指南，在 **VirtualBox** 的 Ubuntu 16.04 64-bit 客户端中部署 typearmor**)  

## 部署

- 安装 Dyninst 10.1.0 并配置 PATH 环境变量 (**请参考 `ReCFA-dev` 仓库的指南**)  
- 安装 zstandard  
- （可选）编译用于调用点过滤（call-site filtering）的 preCFG：  
  ```bash
  cd src/preCFG
  make
  make install
  ```
- （可选）编译调用点过滤器：  
  ```bash
  cd src/csfilter
  make
  make install
  ```
- 生成用于调用点过滤的 `.dot` 和 `.asm` 文件，然后执行过滤操作：  
  ```bash
  ./prepare_csfiltering.sh gcc
  ./prepare_csfiltering.sh llvm
  ```
  **（此步骤的输出文件位于 `spec_gcc/O0` 和 `spec_llvm/O0`，对于每个二进制文件，例如 `bzip2_base.gcc_O0`，该步骤会生成 `.dot`、`.filtered` 和 `.filtered.map` 文件）**  

- （可选）编译二进制变异器（mutator），用于通过 Dyninst 进行静态插桩：  
  ```bash
  cd src/mutator
  make
  make install
  ```
- 使用变异器对二进制文件进行插桩：  
  ```bash
  ./instrument.sh gcc
  ./instrument.sh llvm
  ```
  **（此步骤的输出文件位于 `spec_gcc/O0` 和 `spec_llvm/O0`，例如 `bzip2_base.gcc_O0`，会生成插桩后的二进制文件 `bzip2_base.gcc_O0_instru`）**  

- **下一步需运行插桩后的二进制文件，并使用 SPEC CPU 2k6 基准测试的标准负载生成控制流事件。由于 SPEC CPU 2k6 无法公开发布，我们假设该步骤已完成。请下载以下 ZIP 文件以获取控制流事件数据：**  
  - [re-gcc.zip](https://drive.google.com/file/d/10WiR7L3w_sRVK1JG6Tu8OKVNexhmwhB6/view?usp=sharing)  
  - [re-llvm.zip](https://drive.google.com/file/d/1aoc1BppBAKIRDSAT0wsxq9WbkZ_rz_jS/view?usp=sharing)  

  请将 `re-gcc.zip` 放入 `spec_gcc/O0` 目录并解压缩，即可获得控制流事件文件。例如，`spec_gcc/O0/bzip2_base.gcc_O0_instru` 的运行时事件存储在 `spec_gcc/O0/bzip2_base.gcc_O0_instru-re`。  

- （可选）编译事件折叠（folding）和贪心压缩（greedy compression）程序：  
  ```bash
  cd src/folding
  ./build.sh
  ```
- 执行 prover 端控制流事件的折叠和贪心压缩：  
  ```bash
  ./compress.sh gcc
  ./compress.sh llvm
  ```
  该过程将生成：
  - **折叠后的运行时控制流事件**（例如 `bzip2_base.gcc_O0_instru-re_folded`）  
  - **贪心压缩结果**（例如 `bzip2_base.gcc_O0_instru-re_folded_gr`）  
  - **zstandard 压缩结果**（例如 `bzip2_base.gcc_O0_instru-re_folded_gr.zst`）  

- **准备验证器（Verifier）**
  - （可选）编译验证器：  
  ```bash
  cd src/verifier
  ./build.sh
  ```

- **生成 CFI 策略映射 `F`**（需要打补丁的 typearmor）。  
  **请按照 `ReCFA-dev` 的指南部署并打补丁 typearmor（评测人员可跳过该步骤，预生成的策略文件位于 `policy/F/`）。**  
  - 将原始（未插桩）SPEC2k6 二进制文件放入 `typearmor/server-bins` 目录。然后执行：  
    ```bash
    cd typearmor/server-bins
    ../run-ta-static.sh ./bzip2_base.gcc_O0
    ```
  - 生成的策略文件存放在 `typearmor/out/` 目录，例如 `typearmor/out/binfo.bzip2_base.gcc_O0`。  
  - 将所有策略文件移动到 `ReCFA` 仓库的 `policy/` 目录，以供验证器使用。  

- 运行验证器（确保策略文件正确部署在 `policy/` 目录下）：  
  ```bash
  ./verify.sh gcc
  ./verify.sh llvm
  ```
  验证器会在控制台输出认证结果。  

## 目录结构  

- `spec_gcc`, `spec_llvm`：ReCFA 基准测试评估的工作目录  
- `bin`：ReCFA 的可执行文件  
- `src`：ReCFA 主要模块的源代码  
  - `preCFG`：使用 Dyninst 生成 `.dot` 文件（用于调用点过滤和验证）  
  - `csfilter`：生成被跳过的直接调用点  
  - `mutator`：变异器程序，输入原始二进制文件并插桩为 prover 二进制文件  
  - `folding`：控制流事件的折叠与贪心压缩  
  - `verifier`：验证器程序，使用 CFI 策略检查 prover 的控制流完整性  
- `lib`：控制流折叠和贪心压缩所需的共享库  
- `policy`：CFI 策略文件  