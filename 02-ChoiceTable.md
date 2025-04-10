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

1. 通过Corpus和CallPairMap，对includedCalls初始化；
2. 而后构建choicetable，并enablego；
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

json格式的文件会在extract_syscall_entry阶段，通过idx(内核版本)和xidx(目标点位)来获取。

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
func main() {
	// ...
	if err := manager.Call("Manager.Check", r.CheckResult, &includedCalls); err != nil {
		log.Fatalf("Manager.Check call failed: %v", err)
	}
	// ...
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

### BuildChoiceTable

在syz-fuzzer/fuzzer.go的main函数中通过下面代码被初始化：

```go
type Fuzzer struct {
	// ...
	choiceTable       *prog.ChoiceTable
	// ...
}

type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall

	GoEnable  bool
	startTime time.Time
	CallPairSelector												// 后面会详解
}

func main() {
	// ...
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)						// corpus最初为空，calls为系统支持的calls，BuildChoiceTable的过程和syzkaller相同
	fuzzer.choiceTable.EnableGo(r.CallPairMap, r.RpcCallPairMap, fuzzer.corpus, fuzzer.startTime, r.HitIndex)	// 后面详解
	// ...

```

### EnableGo

在prog/direct.go中定义了EnableGo的过程：

```go
，// 依照CallPairMap(静态)和rpcCallPairMap(动态，包含dist)来对ChoiceTable的CallPairSelector做初始化
func (ct *ChoiceTable) EnableGo(cpMap CallPairMap, rpcCPMap RpcCallPairMap, corpus []*Prog, startTime time.Time, hitIndex uint32) {
	cpInfos := make([]CallPairInfo, 0, len(cpMap)*3)						// 初始化 CallPairInfo 列表和infoIdxMap索引映射
	infoIdxMap := make(map[int]map[int]int, len(cpMap))
	allPrio := 0
	for tcall, rcalls := range cpMap {								// 遍历CallPairMap的所有调用对（Tcall → []Rcall）
		if !ct.Enabled(tcall) {
			continue
		}
		rpcRcallMap, ok1 := rpcCPMap[tcall]
		tmp := append(rcalls, -1)								// 处理每个Rcall（包括无关联调用 Rcall=-1）
		rIdxMap := make(map[int]int)
		for _, rcall := range tmp {
			if rcall != -1 && !ct.Enabled(rcall) {
				continue
			}
			hasAdd := false
			if ok1 {
				if dists2, ok2 := rpcRcallMap[rcall]; ok2 {				// 从 rpcCallPairMap 加载历史距离数据（如有）
					prio := distance2Prio(calcDistSum(dists2), len(dists2))
					cpInfos = append(cpInfos, CallPairInfo{
						Tcall: tcall,
						Rcall: rcall,
						Prio:  prio,
						Dists: dists2,
					})
					allPrio += prio
					hasAdd = true
				}
			}
			if !hasAdd {									// 默认优先级（无历史数据时），有关联prio=1，无关联prio=0
				prio := 1
				if rcall == -1 {
					prio = 0
				}
				cpInfos = append(cpInfos, CallPairInfo{
					Tcall: tcall,
					Rcall: rcall,
					Prio:  prio,
					Dists: make([]uint32, 0, 5),
				})
				allPrio += prio
			}
			rIdxMap[rcall] = len(cpInfos) - 1
		}
		// targetCalls = append(targetCalls, tcall)
		infoIdxMap[tcall] = rIdxMap
	}
	if len(cpInfos) == 0 {
		panic("all target calls are disabled")
	}

	ct.GoEnable = true										// 更新ChoiceTable中的CallPairSelector
	ct.startTime = startTime
	ct.CallPairSelector.hitIndex = hitIndex
	ct.CallPairSelector.callPairInfos = cpInfos
	ct.CallPairSelector.prioSum = allPrio
	ct.CallPairSelector.infoIdxMap = infoIdxMap
}
```

### CallPairSelector

BuildChoiceTable将ChoiceTable的普通内容填写(syzakller)，EnableGo将ChoiceTable的系统调用对内容填写(syzdirect)，即CallPairSelector，定义在prog/direct.go：

```go
type CallPairSelector struct {
	hitIndex          uint32
	prioSum           int
	lastHitDataUpdate time.Time
	isUpdated     bool
	callPairInfos []CallPairInfo
	infoIdxMap    map[int]map[int]int
	mu sync.RWMutex
}

type CallPairInfo struct {
	Tcall int
	Rcall int
	Dists []uint32
	Prio int
}

// CallPairSelector负责存储和管理调用对及其距离信息，根据距离信息计算每个调用对的优先级，根据优先级随机选择调用对；
// EnableGo方法从cpMap和rpcCPMap构建调用对信息，计算初始优先级；
// UpdateCallDistance根据程序中的Tcall和Rcall找到对应的CallPairInfo，将新距离插入到Dists数组中，重新计算优先级
// SelectorCallPair根据优先级随机选择调用对
// distance2Prio实现距离到优先级的转换
```

下面将分别记录对于CallPairSelector的一些方法：

#### UpdateCallDistance

```go
// 每个Prog都包含调用对信息和距离
type Prog struct {
	Target   *Target
	Calls    []*Call
	Comments []string
	ProgExtra
}

type ProgExtra struct {
	Dist  uint32
	Tcall *Call
	Rcall *Call
}

// loop->triageInput->UpdateCallDistance
// triageInput会多次执行程序以确定信号的稳定性，进行最小化，并将程序加入到语料库中
// 如果该程序中Tcall和Rcall的距离有效，则会调用UpdateCallDistance来对距离和优先级做更新
func (selector *CallPairSelector) UpdateCallDistance(p *Prog, dist uint32) {
	if dist == InvalidDist {
		return
	}
	selector.mu.Lock()
	defer selector.mu.Unlock()
	tcallId := p.Tcall.Meta.ID								// 获取程序的Tcall和Rcall
	rcallId := -1
	if p.Rcall != nil {
		rcallId = p.Rcall.Meta.ID
	}
	infoIdx := selector.infoIdxMap[tcallId][rcallId]					// 获取Tcall&Rcall的系统调用对信息CallPairInfo
	info := &selector.callPairInfos[infoIdx]
	dists := info.Dists
	idx, shouldRet := locateIndex(dists, dist)						// 定位是否要将新距离插入到距离数组中，以及确定要插入的位置
	if shouldRet {
		return
	}
	prevDistSum := calcDistSum(dists)
	if idx == len(dists) {									// 如果新距离应该插入到数组末尾
		dists = append(dists, dist)
	} else {
		if len(dists) >= 5 {
			dists = dists[:4]							// 如果数组已满(长度>=5)，截断只保留前4个
		}
		if idx == 0 {									// 如果新距离应该插入到数组开头
			right := len(dists) - 1
			for right >= 0 && 2*dist < dists[right] {				// 数组中的最大元组必须小于等于最小元素的两倍，所以需要筛选掉大于新距离两倍的距离
				right--
			}
			if right >= 0 {
				dists = append([]uint32{dist}, dists[:right+1]...)
			} else {
				dists = []uint32{dist}
			}
		} else {									// 对于中间位置的插入
			tmp := append([]uint32{dist}, dists[idx:]...)
			dists = append(dists[:idx], tmp...)
		}
	}
	currDistSum := calcDistSum(dists)
	info.Dists = dists
	if prevDistSum != currDistSum {								// CallPairInfo的距离数组和变化时，更新优先级
		selector.prioSum = selector.prioSum - info.Prio
		info.Prio = distance2Prio(currDistSum, len(info.Dists))
		selector.prioSum += info.Prio
		selector.isUpdated = true
	}
}

// 在dists中找到dist的位置
func locateIndex(dists []uint32, dist uint32) (int, bool) {
	idx := len(dists) - 1
	for idx >= 0 {										// 找到第一个不大于新距离的元素，停止查找
		if dists[idx] > dist {
			idx -= 1
		} else {
			break
		}
	}
	idx += 1
	if idx >= 5 || (len(dists) > 0 && CallPairLimitMulti*dists[0] < dist) {			// 数组已满且新距离较大 或 新距离是原最小距离的两倍以上，则不该加入新距离
		return idx, true
	}
	return idx, false
}

// 当CallPairInfo的Dists和变化时，更新优先级
func distance2Prio(distSum uint32, distSize int) int {
	var prio int
	dist := float64(distSum) / float64(distSize)						// 计算平均距离，根据平均距离范围采取不同的优先级计算策略
	if dist < 1000 {									// 小于1000，指数衰减，距离越小，优先级越高
		prio = int(1000 * math.Exp(dist*(-0.002)))
	} else {
		left, right := 0.0, 0.0
		switch int(dist / 1000) {							// 大于1000，将距离按每1000为一个区间划分
		case 1:
			left, right = 135, 48
		case 2:
			left, right = 48, 16
		case 3:
			left, right = 16, 8
		case 4:
			left, right = 8, 4
		case 5:
			left, right = 4, 2
		}
		if left == right {								// 大于6000，prio为1
			prio = 1
		} else {
			prio = int(left - (left-right)*(float64(int(dist)%1000))/1000.0)	// 线性插值计算
		}
	}
	return prio
}
```

#### SelectCallPair

```go
// loop->GenerateInGo->SelectCallPair
// loop->Mutate->FixExtraCalls->SelectCallPair
// 生成或变异程序，都会需要选择系统调用对
func (selector *CallPairSelector) SelectCallPair(r *rand.Rand) (int, int) {
	selector.mu.RLock()
	defer selector.mu.RUnlock()
	if selector.prioSum == 0 {									// 优先级为0，随机选择，系统调用之间均无关联
		idx := r.Intn(len(selector.callPairInfos))
		info := &selector.callPairInfos[idx]
		return info.Tcall, info.Rcall
	}
	randVal := r.Intn(selector.prioSum)
	for i := range selector.callPairInfos {								// 累积优先级加权选择
		info := &selector.callPairInfos[i]
		if info.Prio > randVal {
			return info.Tcall, info.Rcall
		}
		randVal -= info.Prio
	}
	log.Fatalf("what ??????")
	return -1, -1
}

// 下面分别说明生成和变异两种情况

// 生成
// 在loop中，当语料库为空 或 完成一个周期时，会调用GenerateInGo生成测试程序
func (target *Target) GenerateInGo(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	if !ct.GoEnable {
		return target.Generate(rs, ncalls, ct)
	}
	tcallId, rcallId := ct.SelectCallPair(rand.New(rs))						// 选择一个调用对
	// log.Printf("tcall id: %v, rcall id: %v\n", tcallId, rcallId)
	return target.generateHelper(ct, rs, ncalls, tcallId, rcallId)					// generateHelper会根据调用对生成程序
}

func (target *Target) generateHelper(ct *ChoiceTable, rs rand.Source, ncalls, tcallId, rcallId int) *Prog {
	var rcall *Call
	s := newState(target, ct, nil)
	r := newRand(target, rs)
	p := &Prog{											// 初始化Prog p
		Target: target,
		ProgExtra: ProgExtra{
			Dist: InvalidDist,
		},
	}

	if rcallId != -1 {										// 处理Rcall，后续会说明generateParticularCall
		rcalls := r.generateParticularCall(s, target.Syscalls[rcallId])
		for _, c := range rcalls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
		rcall = rcalls[len(rcalls)-1]
	}

	for len(p.Calls) < ncalls-1 {									// 填充中间调用，后续会说明generateCall
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}

	r.rcall = rcall
	targetCalls := r.generateParticularCall(s, r.target.Syscalls[tcallId])				// 处理Tcall
	p.Rcall = rcall
	p.Tcall = targetCalls[len(targetCalls)-1]

	rmIdx := len(p.Calls) - 1
	if rmIdx < 0 {
		rmIdx = 0
	}
	p.Calls = append(p.Calls, targetCalls...)
	for len(p.Calls) > ncalls {									// 调整程序长度
		isSucc := p.RemoveCall(rmIdx)
		if !isSucc && rmIdx == 0 {
			rmIdx = 1
		} else if rmIdx > 0 {
			rmIdx--
		}
	}
	return p
}

// 变异
// 当程序需要变异时，变异之后的程序的调用对信息可能被破坏，这时需要对程序p修复，故用到了SelectCallPair
func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
	r := newRand(p.Target, rs)									// 初始化
	if ncalls < len(p.Calls) {
		ncalls = len(p.Calls)
	}
	ctx := &mutator{
		p:      p,
		r:      r,
		ncalls: ncalls,
		ct:     ct,
		corpus: corpus,
	}
	for stop, ok := false, false; !stop; stop = ok && len(p.Calls) != 0 && r.oneOf(3) {		// 执行变异操作
		switch {
		case r.oneOf(5):
			// Not all calls have anything squashable,
			// so this has lower priority in reality.
			ok = ctx.squashAny()								// 尝试压缩复杂指针
		case r.nOutOf(1, 100):
			ok = ctx.splice()								// 程序拼接
		case r.nOutOf(20, 31):
			x := float64(time.Since(ct.startTime) / time.Minute)				// 随时间变化的混合变异策略
			y0 := math.Pow(20, x/(-50)) / 2
			y1 := y0 + 0.5
			y2 := -y0 + 1.0
			if y1 > r.Float64() {
				rcallIdx := getCallIndexByPtr(ctx.p.Rcall, ctx.p.Calls)
				if rcallIdx != -1 && r.oneOf(2) {
					ok = ctx.mutateArg(rcallIdx)
				} else {
					ok = ctx.mutateArg(getCallIndexByPtr(ctx.p.Tcall, ctx.p.Calls))
				}
			}
			if y2 > r.Float64() {
				ok = ok || ctx.insertCall()
			}
		case r.nOutOf(10, 11):
			ok = ctx.mutateArg(-1)								// 随机变异参数
		default:
			ok = ctx.removeCall()								// 移除随机调用
		}
	}
	if p.Tcall == nil {
		p.Target.FixExtraCalls(p, r.Rand, ct, RecommendedCalls, nil)				// 如果变异破坏了目标调用对关系，调用FixExtraCalls修复，该函数和generateHelper类似
	}
	p.sanitizeFix()											// 确保程序结构有效
	p.debugValidate()										// 验证
	if got := len(p.Calls); got < 1 || got > ncalls {
		panic(fmt.Sprintf("bad number of calls after mutation: %v, want [1, %v]", got, ncalls))
	}
}
```

HasTcall

generateCandidateInputInGo

loop

poll

generateParticularCall

generateCall
