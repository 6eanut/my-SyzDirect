# ChoiceTable

```go
type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall

	GoEnable  bool
	startTime time.Time
	CallPairSelector
}
```

fuzzer.go的main函数为入手点：

1. 先对includedCalls初始化；
2. 而后构建choicetable；
3. 而后关注loop和poll两个函数；

## 关键函数/变量

### CallPairMap

含义：Target-Relates Call Pairs，Tcall ID->Rcall IDs

```go
type CallPairMap map[int][]int
```

对CallPairMap的初始化：

```go
type RawCallPair struct {
	Target string
	Relate []string
}

func CallPairFromFile(filename string, target *Target) CallPairMap {			// 从json文件读取Tcall和Rcalls，并转化为CallPairMap格式
	if filename == "" {
		return nil
	}
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Printf("open callfile %v with err: %v\n", filename, err)
		return nil
	}
	var rawCallPairs []RawCallPair							// 先将json转化成[]RawCallPair，Tcall和Rcall都用string来表示
	err = json.Unmarshal(b, &rawCallPairs)
	if err != nil {
		log.Fatalf("call pair unmarshal file %v err: %v\n", filename, err)
	}

	str2Calls := func(call string) []int {
		var res []int
		for _, meta := range target.Syscalls {
			if matchSyscall(meta.Name, call) {
				res = append(res, meta.ID)
			}
		}
		if len(res) == 0 {
			log.Printf("unknown input call:%v\n", call)
		}
		return res
	}

	tmpCallMap := make(map[int]map[int]bool, len(rawCallPairs))			// 将[]RawCallPair转化成tmpCallMap
	for _, rawCallPair := range rawCallPairs {					// Tcall和Rcall由用string表示转化成用ID表示，并用map去重
		tcalls := str2Calls(rawCallPair.Target)
		for _, tcall := range tcalls {
			rcallMap := tmpCallMap[tcall]
			if rcallMap == nil {
				rcallMap = make(map[int]bool, len(rawCallPair.Relate))
				tmpCallMap[tcall] = rcallMap
			}
			for _, rawRCall := range rawCallPair.Relate {
				for _, rc := range str2Calls(rawRCall) {
					rcallMap[rc] = true
				}
			}
		}
	}
	callPairMap := make(CallPairMap, len(tmpCallMap))				// 将tmpCallMap转化成CallPairMap
	for tcall, rcallMap := range tmpCallMap {					// 将map转换成[]，并排序
		keys := make([]int, 0, len(rcallMap))
		for k := range rcallMap {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i] < keys[j]
		})
		callPairMap[tcall] = keys
	}
	return callPairMap
}
```




### includedCalls

含义：Tcall->Rcall->included

```go
var includedCalls map[int]map[int]bool
```

在syz-fuzzer/fuzzer.go的main函数中通过下面代码被初始化：

```go
// manager.Call() 是一个 RPC 调用，它会向 manager 发送 "Manager.Check" 请求，并传递 r.CheckResult 作为参数，包含可用的系统调用列表等。
// manager 端处理这个请求后，会将结果通过第三个参数 &includedCalls 返回。这里的 &includedCalls 是一个指针，所以 manager 可以通过这个指针来修改 includedCalls 的值。
// 这个调用初始化了 includedCalls 这个 map，它会被填充为 manager 返回的数据结构，即一个嵌套的 map map[int]map[int]bool，表示已经包含的调用对。
// 如果调用失败，会通过 log.Fatalf 终止程序。
if err := manager.Call("Manager.Check", r.CheckResult, &includedCalls); err != nil {
	log.Fatalf("Manager.Check call failed: %v", err)
}
```

在syz-manager/rpc.go的Check函数中定义了如下过程：

```go
// serv.targetEnabledSyscalls由a.EnabledCalls转换而来
func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *map[int]map[int]bool) error {
    // ...
    includedCalls := serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
    // ...
    *r = includedCalls
    return nil
}
```

在syz-manager/manager.go的machineChecked函数中定义了如下过程：

```go
func (mgr *Manager) machineChecked(a *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool) map[int]map[int]bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.checkResult = a
	mgr.targetEnabledSyscalls = enabledSyscalls
	mgr.target.UpdateGlobs(a.GlobFiles)
	tmp := mgr.loadCorpus()
	mgr.firstConnect = time.Now()
	return tmp
}
```

在syz-manager/manager.go的loadCorpus函数中定义了如下过程：

```go
// loadCorpus函数的作用是加载持久化语料库，并利用loadProg将符合条件的程序加入候选队列
// syzdirect在该过程中获得Tcalls，并指导loadProg，筛选出包含Tcall的程序，而后初始化includedCalls
func (mgr *Manager) loadCorpus() map[int]map[int]bool {
	// ...
	rawTcalls := mgr.callPairMap.GetRawTargetCalls(mgr.target)			// 获得Tcalls
	for key, rec := range mgr.corpusDB.Records {					// 加载持久化语料库
		if !mgr.loadProg(rec.Val, minimized, smashed, rawTcalls) {		// 利用loadProg将符合条件的程序加入候选队列，Tcalls指导loadProg的过程
			mgr.corpusDB.Delete(key)
			broken++
		}
	}
	// 初始化includedCalls的过程
	// ...
}
```

获得Tcalls？指导loadProg的过程？初始化includedCalls的过程？将在这里说明：

```go
// 获得Tcalls
func (cpMap CallPairMap) GetRawTargetCalls(target *Target) map[int]bool {		// 将CallPairMap类型的cpMap转化成map[int]bool类型的rawTcalls，即只保留Tcall
	rawTcalls := make(map[int]bool, len(cpMap))
	for tcall := range cpMap {
		callName := target.Syscalls[tcall].Name					// 处理带有 "_rf1" 或 "$tmp_rf1" 后缀的变异调用
		if strings.HasSuffix(callName, "_rf1") {
			oriName := callName[:len(callName)-4]				// 将变异调用还原为原始调用
			if strings.HasSuffix(callName, "$tmp_rf1") {
				oriName = callName[:len(callName)-8]
			}
			rawTcalls[target.SyscallMap[oriName].ID] = true
		} else {
			rawTcalls[tcall] = true
		}
	}
	return rawTcalls
}

// 指导loadProg的过程
func (mgr *Manager) loadProg(data []byte, minimized, smashed bool, rawTcalls map[int]bool) bool {
	// ...
	hasTarget := false								// hasTarget记录prog是否包含Tcall
	for _, call := range p.Calls {							// 遍历prog中的每个call，检查是不是Tcall
		if rawTcalls[call.Meta.ID] {
			hasTarget = true
			break
		}
	}
	if !hasTarget {									// 如果prog不含Tcall，那么不会被加入到candidates中
		return false
	}
	mgr.candidates = append(mgr.candidates, rpctype.Candidate{			// 如果prog包含Tcall，那么会加入到candidates中
		Prog:      data,
		Minimized: minimized,
		Smashed:   smashed,
	})
	return true
}

// 初始化includedCalls的过程
func (mgr *Manager) loadCorpus() map[int]map[int]bool {
	// ...
	includedCalls := make(map[int]map[int]bool)
	for i := range mgr.candidates {								// 遍历candidates中的每个prog
		p, err := mgr.target.Deserialize(mgr.candidates[i].Prog, prog.NonStrict)
		if err != nil {
			log.Fatalf("should success")
		}
		for i := len(p.Calls) - 1; i >= 0; i-- {					// 从prog中逆序遍历call，找到所有Tcalls，每个Tcall对应的是Rcalls
			if rcalls, ok := mgr.serv.callPairMap[p.Calls[i].Meta.ID]; ok {
				tcallId, rcallId := p.Calls[i].Meta.ID, -1
				for j := 0; j < i && rcallId != -1; j++ {			// 从prog中顺序遍历call直到Tcall，看是否在Rcalls中
					for _, rcall := range rcalls {
						if rcall == p.Calls[j].Meta.ID {
							rcallId = rcall				// 如果找到了Tcall对应的Rcall，则记录，否则Rcall为-1
							break
						}
					}
				}
				if includedCalls[tcallId] == nil {				// 只要找到Tcall，无论找没找到Rcall，都写includedCalls
					includedCalls[tcallId] = make(map[int]bool)
				}
				includedCalls[tcallId][rcallId] = true
				break
			}
		}
	}
	log.Logf(0, "[syzgo] includedCalls: %v", includedCalls)
	// ...
	return includedCalls
}
```









EnableGo

HasTcall

generateCandidateInputInGo

loop

poll
