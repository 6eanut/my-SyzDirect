# SyzDirect and Syzkaller

Makefile：添加了feature组件

**syz_sig和relate2context2.json**：定义了系统调用变体(syscall variants)，后续需要详细查看其和syzkaller之间的区别

vendor/emirpasic/gods：使用了gods，即go语言里的容器、队列、树等数据结构

**tools/direct**：分析系统调用关系和模糊测试结果

**syz-manager**：callPairMap prog.CallPairMap需要分析，maxDistance Stat和minDistance Stat需要分析，

**syz-fuzzer**：弃用corpusPrios，改用distanceGroup；涉及到chooseProgram和addInputToCorpus；弄明白hitCount

**syz-features**：推测是syscall argument refinement，看看和/pkg/compiler/callrefine.go有啥关系

**prog/direct.go**：很关键，专门看；generation、minimization、mutation、prio、prog等都有变化

executor：执行器也有变化，但感觉不是特别重要

---

先看syz-fuzzer吧！

## 20250407

通过看syzkaller得知，理清核心部分就是理清choicetable和corpus的优先级定义、更新策略和选择策略，故对于syzdirect同理。

今天先争取对corpus的部分进行梳理。

因为syzdirect是在基于老版本的syzkaller进行的改写，所以后面不仅需要看syzdirect，还需要看当时的syzkaller，因为之前看的syzkaller是最新版的。
