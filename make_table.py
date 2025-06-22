"""
This script is used to extract bibtex ref(\\cite variable) from tex src,
and match it with a given table's tool-name column by tool name.
"""

import re
from os import path

import pandas as pd
from langchain.chat_models import init_chat_model
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

INPUT_XLSX = path.join(path.dirname(__file__), "input.xlsx")
OUTPUT_CSV = path.join(path.dirname(__file__), "output.csv")
_2_RACE_DATA = r"""
\section{竞争型漏洞}
并发相关的逻辑漏洞，特别是请求竞争（Request Races）和条件竞争（Race Conditions），已成为现代 Web 应用和移动应用安全的新兴关键风险点。近年来的研究提出了多种自动化检测方法，其目标和技术手段呈现清晰的演进脉络。
   Warszawski 和 Bailis (2017)~\cite{10.1145/3035918.3064037}针对数据库支持的 Web 应用，率先提出了\textbf{ACIDRain系统}。其核心是\textbf{基于 SQL 日志和 Schema 的抽象异常检测} (2AD)。该方法旨在解决弱隔离级别和 API 级别事务划分下的并发安全问题。2AD 通过自动推导 API 间的冲突操作（如读写、写写冲突）并识别可能导致业务不一致的非平凡依赖环 (non-trivial dependency cycles)，能够跨编程语言和平台检测并发漏洞。ACIDRain 有效证明了自动化手段在发掘\textbf{复杂并发错误（如丢失更新、违反不变约束）和潜在攻击场景方面的可行性}。 
   
   Qiu 等 (2021)~\cite{10.1145/3468264.3468594}开发了\textbf{ReqRacer系统}， 创新性地利用\textbf{依赖图}精确建模 Web 应用中\textbf{复杂的 “happens-before” 关系}，涵盖了\textbf{请求 - 响应时序、主键依赖性}等多种约束。更重要的是，它引入了执行\textbf{轨迹重放机制}来验证所发现的竞态路径的实际可行性。这种结合依赖分析和重放验证的方法，不仅能够检测已知的请求竞态 Bug，还能自动化地定位跨请求处理器（handler）和跨资源访问的真实竞态，并成功揭露了新型竞态攻击模式导致的严重安全漏洞。
   
   Du 等 (2022)~\cite{10.1145/3548606.3560666} 聚焦Android 外部存储上因文件操作不当导致的竞争条件问题，设计了\textbf{RECAST系统}。RECAST 的核心在于其大规模文件操作事件处理流程：客户端利用FileObserver收集详尽的\textbf{文件操作事件}（类型、时间戳、路径），服务器端进行事件过滤、关联、排序，并据此推断\textbf{文件操作流程模式和命名规则}以识别潜在竞争窗口。
   
   Guo 等 (2024)~\cite{10589749} 则关注移动应用内部复杂并发模型（多线程 + 异步消息）导致的数据竞争（data races），提出了\textbf{PredRacer}。PredRacer 采用预测性方法：通过插桩捕获运行时轨迹，基于\textbf{程序偏序关系}对轨迹事件进行重排序生成包含潜在数据竞争的新事件序列，并检查序列的可行性。其创新点在于\textbf{显式建模安卓特有的 “happens-before” 关系}以减少误报，并利用线程化技术处理单线程回调间竞争，有效应对了移动环境的并发复杂性。 
   
   Zhang 等 (2022)~\cite{280044} 和 Zhang 等 (2024) ~\cite{10506090} 的研究深入到移动应用内应用（App-in-App）生态系统中由并发和校验不当引发的\textbf{身份混淆和跨方委托资源安全风险}。~\cite{280044} 首次系统揭示了超级应用（Super-App）在向子应用（Sub-App）授权时依赖的三种身份机制（域名、子应用 ID、能力 - capability）存在的混淆漏洞（包括利用渲染与授权时间差进行竞争条件攻击），在主流应用生态中广泛存在，可能导致严重后果。随后的 ~\cite{10506090} 进一步聚焦 \textbf{CPDR 的安全规则}落实问题，提出了伪装攻击、数据驱动攻击和信道劫持攻击等威胁模型，强调了跨生态系统中此类漏洞的联动风险。
   
   \textbf{DDRace} (2023)~\cite{10.5555/3620237.3620397} 针对 Linux 内核驱动中高危害的并发性释放后使用漏洞（Concurrency UAF），提出一种定向并发灰盒模糊测试技术路线。其核心是通过轻量级动态追踪与静态路径分析精准识别目标内存对象的\textbf{竞态操作对（FREE/USE 指令对）}，构建约束导向的漏洞触发空间；进而设计线程调度定向引导机制，融合竞态对\textbf{交错路径覆盖反馈（RPIP）}与\textbf{漏洞约束距离模型}，动态量化线程交错时序的新颖性与漏洞逼近程度，优先探索高危并发路径；同时结合自适应\textbf{内核快照技术}稳定目标状态，实现复杂并发时序条件的可靠复现。该方案显著优化了并发漏洞的检测效率与精准性，在真实驱动中验证了其技术优势。
   
   \textbf{HistLock +} (2018)~\cite{8375648} 针对并发数据竞争检测的核心技术路线，通过EL-Span 分区机制与锁释放计数器（LRC） 动态划分线程执行区间，基于锁集单调性定理（同一 EL-Span 内锁集仅增不减）设计轻量级访问维护策略：对每个共享内存位置仅保留分区内首个关键访问（写操作优先，无写则留读），完全避免传统混合检测的锁集比较开销；同时结合修改的 \textbf{Happens-Before（mHB）关系}验证并发冲突，实现无假阳性的完备竞争检测。该方案通过\textbf{开源框架 HiSuS} 在 Linux 内核与 PARSEC 等应用中验证，较主流方案 MultiLock-HB 提速 122\%，内存开销降低 28\%，并\textbf{发现多个未知 CVE 漏洞}，显著提升高并发场景下的检测效率与精准性。
   
   \textbf{Razzer} (2019)~\cite{8835326} 针对 Linux 内核数据竞争漏洞，提出混合导向灰盒模糊测试技术路线：首先通过\textbf{轻量级静态指针分析(SVF 框架)} 在模块化内核分区内精确定位潜在竞争共享变量访问对（RacePairₛᵥ），将搜索空间压缩至内存操作指令对的 0.05\% 以下；进而设计两阶段动态触发机制， 首阶段生成\textbf{覆盖目标点的单线程程序（Pₛᵥ）}，次阶段通过\textbf{超线程调度器}（集成在 QEMU/KVM 虚拟化层）实施按核断点挂起、hcall\_set\_order () 线程时序强制控制及地址一致性动态验证，实现竞态条件的确定性触发；最终结合 KASAN 等内置检测器自动化验证并输出可复现漏洞报告。
   \textbf{SDRacer} (2020)~\cite{9072666} 针对中断驱动型嵌入式软件的竞态条件漏洞，构建了“\textbf{静态检测 - 路径精化 - 动态验证 - 自动修复}” 的全流程技术路线：首先基于指针别名分析与中断状态位向量（INTB）建模，精确定位关键冲突访问对（应用任务 / ISR 间共享资源写操作）；继而通过符号化硬件寄存器输入与指令距离优先级引导的跨上下文控制流分析（ICCFG），结合 SMT 求解器精炼可达路径；进而利用Simics 虚拟化平台实现中断精确调度（按核断点挂起与hcall\_set\_order()时序控制），触发并验证竞态危害；最终依据\textbf{工业实践生成中断开关（IDE）}与\textbf{自旋锁扩展（AL/ECS）} 等多策略修复方案，通过动态验证确保零死锁引入且性能损耗 < 9\%。
"""

_3_ESCALATE_DATA = r"""

\section{越权漏洞}
权限提升漏洞（Privilege Escalation, PE）是Web应用和移动应用安全的核心威胁，检测技术的研究贯穿始终并持续演进，覆盖从传统Web应用到新兴应用内应用（app-in-app）生态系统等广泛场景。

Monshizadeh等(2014)~\cite{10.1145/2660267.2660337} 提出的\textbf{MACE 系统}奠定了基于程序分析的静态检测基础。其核心创新是引入\textbf{授权上下文四元组⟨U, R, S, P⟩}（用户、资源、状态、权限）来抽象安全操作。MACE将控制流、数据流分析与授权变量状态关联，通过符号执行（symbolic execution）和程序切片（program slicing）技术，自动化地识别Web应用中可能导致垂直权限提升（Vertical PE, VPE）和水平权限提升（Horizontal PE, HPE）漏洞的授权逻辑缺陷。这一理论框架为后续\textbf{细粒度对象授权模型和更复杂场景的检测}提供了重要的方法论基础。

随着移动安全重要性凸显，Elsabagh等(2020)~\cite{251554}提出了\textbf{FIRMSCOPE}，针对安卓固件中预装应用存在的权限提升漏洞进行自动挖掘。该系统针对用户无法卸载的高权限预装应用，设计并实现了一种\textbf{上下文敏感、流敏感、字段敏感和部分对象敏感}的新型静态污点分析引擎。其流程包括：固件预处理（解包、提取、反汇编预装应用）、构建过程间控制流图（ICFG）和过程间数据流图（IDFG），最终执行定制的漏洞导向（vulnerability-directed）的污染分析以识别可被外部调用者利用的提权路径（如命令注入、任意应用安装/卸载、代码注入等）。\textbf{通过扫描来自100多家供应商的2017个固件镜像中331,342个预装应用，FIRMSCOPE发现了850个独特漏洞类型（共3,483个实例）}，证明了预装应用生态中权限提升漏洞的普遍性和严重性。

Zhang等(2023)~\cite{10.1145/3605762.3624430}聚焦于应用内应用（app-in-app）生态系统中的提权威胁，提出了\textbf{可信域名泄露攻击（Trusted Domain Compromise Attack, TDCAttack）}。该研究揭示，超级应用通常依赖域名白名单（类似于CSP）约束小程序的资源加载行为，但其安全机制隐含了对白名单内所有域名资产完全可信的错误假设。攻击者可利用白名单域名或其资产的弱点（如子域名接管、过期域名、域内页面存在XSS/开放重定向漏洞）来绕过白名单安全策略。通过自动化提取和扩展11,838个小程序源码中的域名白名单、评估相关资产安全性并进行模板化动态测试，研究者证实主流生态系统均易受此攻击，\textbf{成功识别26个可利用实例}，并揭示其可导致钓鱼攻击、隐私泄露乃至权限提升等严重后果。TDCAttack凸显了在复杂委托场景下，静态信任机制（域名白名单）可能因关联资产的弱点和潜在竞态条件成为特权提升的新通道。

Georgiev等(2014)~\cite{georgiev2014breaking}针对混合移动应用中，Web层的同源策略与原生操作系统的权限模型之间存在的不兼容的问题进行了研究，揭示了一类名为\textbf{fracking}的通用提权漏洞 。该研究首先对PhoneGap等主流混合应用框架开展分析，发现这些框架实现的web层和原生层桥接机制存在缺陷。随后，通过对7,167个真实安卓应用的大规模自动化分析，该研究证实隔离在iframe中的外部恶意Web内容能够利用这些存在缺陷的桥接，绕过\textbf{同源策略}的限制，直接访问用户的通讯录、文件系统等敏感资源。最后，该研究提出了基于能力令牌的\textbf{NOFRAK防御框架}，为每个授权的web域名生成一个\textbf{不可伪造的能力令牌}，并强制在访问本地资源时鉴权，从而修复了该类漏洞。

Hernandez等(2020)~\cite{247662}针对Android系统中强制访问控制（MAC）、自主访问控制（DAC）以及Linux Capabilities等多层安全策略之间相互作用所引发的安全问题，提出了\textbf{BigMAC 分析框架}。该框架通过模拟Android系统的启动过程，基于静态固件重建出一个\textbf{包含所有运行时对象和进程凭证的系统安全快照}。在此基础上，框架对多种安全策略进行联合分析，将抽象的安全策略实例化为攻击图，并进一步将攻击图转换为一组Prolog事实，从而实现对任意起点与终点之间、满足多重策略约束的攻击路径的高效查询。BigMAC 在对\textbf{三星和LG固件}的分析中，发现了多个因策略交互而产生的真实安全隐患，例如非受信任应用能够与内核监控服务或root进程通信，凸显出在多种安全策略共存的系统中，开展联合分析的重要性与必要性。

Wang等(2023)~\cite{10172538} 提出了\textbf{ Taintmini 污点}分析框架，解决了小程序中跨语言、跨页面及跨应用等特性给敏感数据流追踪带来的难题。该框架通过构建通用数据流图(Universal Data Flow Graph, UDFG)，将小程序中 \textbf{WXML 视图层}与 \textbf{JavaScript 逻辑层}的交互进行统一建模，并将抽象的数据流实例化为一个完整的图 。在此基础上，框架能够系统性地追踪和连接不同事件、页面乃至小程序之间的污点传播路径。\textbf{Taintmini在对238,866个微信小程序的分析中，发现了455个通过跨应用传递数据进行合谋攻击的恶意程序}，揭示了小程序生态中隐藏的隐私泄露风险。该研究凸显了对跨域数据流进行自动化分析的重要性，揭示了小程序生态中权限管理的内生性缺陷。

针对小程序中因跨语法数据流、异步执行、复杂的属性链以及函数别名等特性带来的敏感信息泄露追踪难题，Li 等(2024)~\cite{10197457} 提出了自动化分析框架\textbf{MiniTracker}。该框架首先为JavaScript代码构建\textbf{赋值流图(AFG)}并将异步调用转换为等效同步调用，随后通过页面分析器整合渲染层的数据流，并通过工具集分析器搜索函数别名识别额外污点源，最终实现对小程序中敏感数据流的高效精准识别。\textbf{MiniTracker对超过15万个微信小程序进行了大规模分析，发现每个小程序平均存在17.73个潜在隐私泄露点}，其中最常见的是将通过开放API获取的用户敏感信息发送至网络，揭示了小程序中普遍存在的隐私威胁模式。

Lu等(2020)~\cite{10.1145/3372297.3417255} 首次系统性分析了应用内应用（app-in-app）生态中，宿主应用(host-app)作为第三方应用在管理子应用(sub-app)访问系统资源时面临的安全挑战。该研究开发了自动化扫描工具 \textbf{Apinat}，能够对11个主流的应用内应用平台进行分析，并识别其中的\textbf{系统资源暴露、子窗口欺骗、子应用生命周期劫持风险}。Apinat发现所有被测平台均存在安全风险，\textbf{并找到了共计52个新漏洞}。这些风险表明，宿主应用部分取代了操作系统的权限管理职责，但由于其权限管理机制的实现存在缺陷，导致应用内应用生态削弱了现有移动操作系统的安全模型，同时又引入了新的攻击面。该研究揭示了第三方应用构建生态系统时，实现安全管理机制的局限性。
"""

_4_DESIGN_IMPL_DIFF_DATA = r"""



\section{代码设计与实现差异}
软件和系统的安全性高度依赖于代码实现与安全设计规范的一致性，以区块链及零知识证明系统为例。近年研究围绕协议状态机、密码学电路、Layer 2 最终性及金融操作序列等核心场景，提出多种自动化检测方法，以识别实现偏离设计导致的逻辑漏洞。

LOKI (2023)~\cite{ma2023loki} 针对区块链共识协议状态机的复杂性，提出\textbf{状态感知的模糊测试框架}。该框架通过探索协议实现中的\textbf{多维度状态空间}（如节点视图切换、区块同步时序），深度挖掘区块链虚拟机中，违反共识协议安全的代码实现。

在以太坊虚拟机（EVM）等核心组件的实现中，由于其存在多种语言版本和独立开发团队，代码设计与实现差异导致的漏洞尤为突出。 EVMFuzz (2024)~\cite{fu2024evmfuzz} 针对这一问题，率先提出并应用了\textbf{差分模糊测试技术}。它通过生成随机的智能合约代码作为输入，并在多个不同语言（如Go、Python、JavaScript等）实现的EVM上同时执行，然后比较各实现的输出状态（如最终账户余额、Gas消耗、日志等）。\textbf{任何不一致性都表明某个EVM实现存在与规范的偏差}，从而暴露潜在的共识漏洞或安全隐患。

Yang 等人提出的 Fluffy (2021)~\cite{yang2021finding}，则将差分模糊测试拓展到多事务场景，以发现更深层次的以太坊共识错误。该方法通过构造和变异包含多个交易的复杂测试用例，并在多个以太坊客户端（它们内部使用了不同语言实现的EVM）之间进行比对。这种方法通过分析“\textbf{因交易顺序、状态依赖性或复杂交互逻辑}”在不同的以太坊客户端中产生的行为差异，从而发现因为实现与设计差异导致的\textbf{共识漏洞}。

针对零知识证明电路中潜在的电路计算设计与约束实现间的差异，ZKAP (2023)~\cite{wen2024practical} 开发了\textbf{专用静态分析工}具。该方法通过形式化验证电路实现是否满足密码学设计规范（如算术电路约束完整性、公共输入 / 私有输入绑定关系），在部署前主动识别安全隐患（如约束缺失、变量覆盖不全），确保 ZK 系统的可验证安全性。

fAmulet (2024)~\cite{li2024famulet} 聚焦zkRollup 等 Layer 2 方案中的交易最终性保障问题。通过定向模糊测试技术生成交易序列，动态验证“\textbf{状态提交、证明生成、挑战期交互}”等关键流程的实现是否满足设计预期的原子性与不可逆性，有效暴露最终性失效漏洞（如部分状态被恶意回滚）。

DeFiRanger (2023)~\cite{wu2023defiranger} 从金融行为一致性角度切入，设计\textbf{现金流树（Cash Flow Trees）模型与高阶操作序列分析引擎}。通过追踪链上交易的资金流向与操作组合（如闪电贷、流动性操纵），识别实际行为与协议设计目标（如价格稳定性、清算公平性）的系统性偏差，精准检测价格操纵、套利攻击等恶意模式。

加密算法的实现过程也成为逻辑漏洞的重要来源之一。尽管加密算法本身在理论上具有完备性，其在实际编码实现过程中仍可能因语言特性或库差异而引入逻辑漏洞。对此，Zhou等人设计并实现了\textbf{CLFuzz} (2024)~\cite{zhou2023clfuzz}，一种面向加密算法实现的\textbf{语义感知模糊测试器}，旨在弥补传统静态分析和动态模糊测试在处理加密语义复杂性方面的不足。CLFuzz 首先提取密码算法的语义信息（如特定约束与函数签名），据此自适应生成高质量输入以触发潜在缺陷，并引入逻辑交叉检查机制增强漏洞检测能力。

此外，针对安全协议在实现中可能出现的逻辑偏差，Zhao 等人(2025)~\cite{zhao2025aglfuzz}利用\textbf{线性时序逻辑描述协议应有的行为}，并通过自动机判断模糊测试生成的交互序列是否\textbf{违反预期逻辑}。为了提高效率，作者设计了由自动机引导的测试生成算法，最终实现了通\textbf{用测试框架 AGLFuzz}。
"""

_5_INCONSISTENT_DATA = r"""

\section{校验不一致性}

校验不一致性漏洞（表现为安全检查缺失或访问控制逻辑冲突）是系统安全领域持续存在的核心挑战，其检测方法已从基础规则推断演进至跨上下文语义对齐、覆盖代码路径、错误处理逻辑及异构执行环境等多种场景。

Tan等(2008)~\cite{10.5555/1496711.1496737} 提出 \textbf{AutoISES} 系统，首次通过静态分析源代码识别被同一安全检查函数（如 security\_file\_permission()）保护的\textbf{安全敏感操作}（如文件读写）。系统自动化推断安全规则：若某检查函数在多数代码路径中保护一组固定数据访问，则要求该组访问必须受此检查保护。通过对比规则与实际检查分布，可精准定位安全检查缺失的敏感操作，并筛选可能被攻击者利用的漏洞（即检查操作通过系统调用暴露）。

Aafer 等 (2016)~\cite{10.5555/3241094.3241183} 则聚焦安卓定制化生态（如厂商 ROM） 中的安全配置不一致，开发 \textbf{DroidDiff} 工具。该工具系统性识别\textbf{易被修改的安全配置特征}（权限级别、GID 映射、组件可见性等），并从591 个定制 ROM 中提取特征值，通过跨厂商 / 型号 / 区域 / 运营商 / 版本的五类差分分析算法自动识别配置异常，揭示了定制化过程中的系统性风险。

在~\cite{10.5555/3241094.3241183} 基础上，\textbf{AceDroid} (2018)~\cite{aafer2018acedroid} 解决了安卓访问控制检查多样化带来的分析难题。AceDroid对路径上的\textbf{访问控制检查}进行\textbf{统一规范化建模}，通过沿控制流路径将多样化的检查逻辑（例如UID、包名、签名、系统属性）规范化为统一的访问控制范式，并按照谓词逻辑关系正确组合，实现了对形式各异的语义等价检查的精确识别。AceDroid对三星、索尼等厂家的12个ROM镜像进行分析，发现了按键记录、付费短信发送等漏洞，检测出大量由厂商定制引入的不一致性，进一步揭示了定制化引入的安全风险。

Liu 等 (2021)~\cite{10.1145/3460120.3485373} 提出基于对象锚点的相似路径差异检查。该方法首先定位安全操作（权限检查、资源释放）并提取其作用的关键变量作为目标对象，筛选同函数内起止块相同、对象状态和语义相似的路径对，通过\textbf{比对路径对中安全操作的一致性}（一有一无），直接定位潜在检查缺失漏洞 。

Lu 等 (2019)~\cite{236280} 则引入\textbf{语义约束}与\textbf{相对频率}（RF）指标：通过数据流追踪关键变量来源，将条件语句抽象为语义约束，并依据语义相似度对路径分组；在同源路径组内，若某约束高频出现（如 90\% 路径含检查），则缺失该约束的路径被标记为漏洞。该方法本质是将路径间语义约束的校验不一致性作为漏洞检测的核心判据，实现了对约束缺失型漏洞的系统化捕获。

Zhou 等 (2022)~\cite{zhou2022uncovering} 设计了\textbf{IAceFinder}工具，专注检测安卓 Java 层与原生层间的访问控制策略不一致问题。该工具将安卓的权限与uid划分为4个\textbf{特权等级}，随后先后分析JNI方法的Java层服务实现与原生实现，分别将两个函数实现内不同形式的访问控制检查规范为统一的特权等级，最后通过比对两个函数特权检查的\textbf{特权等级差异}，精确发现跨上下文不一致的访问控制缺陷。IAceFinder在14个开源ROM上进行测试，发现了23个可被利用的访问控制不一致缺陷，可导致用户隐私泄露和设备损坏。

Dossche 等 (2024)~\cite{298112} 聚焦函数级错误处理逻辑推断，通过\textbf{提取函数内控制流路径切片}并抽象为包含调用、返回值和条件分支的摘要，利用最长公共子序列（LCS）算法\textbf{匹配相似路径}，基于多数投票原则推导规范化的错误返回值集合。完成上述操作后，通过建立错误返回值与其对应错误处理行为的精准状态映射，系统检测相同返回值下因处理逻辑不一致导致的安全漏洞。

Kobold（2020）~\cite{9152695} 揭示了iOS NSXPC 应用中的\textbf{权限配置不一致性}。该方法抓取\textbf{5700 个热门应用}和 \textbf{10 万个随机应用}，提取其权限配置，发现 17 种仅授予特定开发者的权限（即半私有权限）。然后逆向 iOS 固件 ，提取 Mach 端口与协议信息，通过class-dump工具解析 NSXPC 接口方法名及参数类型。同时分析xpcd\_cache.dylib中的配置缓存，映射 Mach 端口到守护进程。完成上述步骤后，利用动态测试，使用未初始化参数调用 NSXPC 方法，触发异常行为。最后通过人工分析，基于方法名语义和权限不一致性，定位高风险方法。

Shao 等（2016）~\cite{shao2016kratos}提出了\textbf{Kratos}，可以系统性发现 Android 框架中存在的安全策略执行不一致问题。Kratos 通过\textbf{自动构建调用图、标注并分析安全检查流程}，无需预定义全量敏感资源，能自动挖掘多路径下安全策略强制的差异。实证表明，Kratos 在多个 AOSP 及定制 Android 版本上发现了大量高风险漏洞，并显著提升了发现此类系统性策略失效的效率与覆盖面，\textbf{填补了以往需人工分析、覆盖有限的短板}。不过其仍存在路径敏感性不足、隐式流覆盖有限、验证仍需人工辅助等挑战。
"""

_6_MPC_DATA = r"""

\section{权限检查缺失}

权限检查缺失漏洞（Missing Permission Check Vulnerability）是指在访问受保护资源或执行敏感操作前，程序未对请求主体（如用户、进程）进行必要的权限验证，导致越权访问或操作的安全缺陷。

针对操作系统内核，\textbf{PeX系统} (2018)\cite{236362}从内核模块接口的函数指针入手，通过静态解析函数初始化结构与间接调用关系，构建\textbf{函数间权限依赖图}，并系统性验证路径中是否存在缺失、不一致或冗余的权限检查问题。其关键在于利用LLVM IR对结构体偏移的建模，使得在面对大量间接调用和代码复杂度的情况下依然具备良好的扩展性。

在更为复杂的云计算环境中，Lu等人 (2022)\cite{10.1145/3548606.3560589}提出面向\textbf{分布式系统}的权限缺失检测方法。相比PeX依赖精确的静态控制流建模，该方法结合运行时日志与类型推断扩展用户变量集合，并结合静态分析识别异常条件语句，进而捕获关键特权操作路径中是否存在权限判断缺失的情况。这种\textbf{静动态联合分析}方法在面对云系统中高度异构与跨模块访问场景时显示出更强的实际适应性。

除Linux和云系统外，移动操作系统也是权限缺陷高发的环境。\textbf{iService} (2022)~\cite{10.1145/3564625.3568001}聚焦于AppleOS生态，专门分析由XPC/NSXPC机制引发的身份混淆问题。其利用Objective-C消息机制分析系统调用图，并结合苹果官方API列表提取敏感参数定义，通过构建\textbf{Code Property Graph（CPG）}进行跨过程的\textbf{数据流跟踪}，从而捕获未经过验证的IPC输入最终影响敏感操作的漏洞路径。相比PeX和Lu等人工作，iService将研究范围从代码控制路径进一步拓展到敏感参数的数据流语义层面。

在Web安全领域，权限检查缺失问题同样普遍存在。Sun等人 (2011)\cite{10.5555/2028067.2028078}提出了一种基于\textbf{角色化网站地图比对}与\textbf{强制浏览模拟}的静态分析方法，核心聚焦于权限检查缺失漏洞的自动化检测。其技术路径为：通过上下文敏感的静态数据流分析，为不同权限角色（如管理员与普通用户）构建网站地图，显式链接仅出现在高权限角色地图中的页面被识别为特权页面；通过模拟低权限用户直接访问特权页面的强制浏览行为，验证响应内容是否与高权限访问结果一致。若响应完全匹配（如 CFG 结构相同且无重定向 / 错误），则判定该特权页面存在权限检查缺失漏洞。该方法首次将前端可见性差异（角色化网站地图）作为后端访问控制缺失的检测依据，在 7 个 PHP 应用中成功识别 8 个权限缺失漏洞（含 \textbf{4 个 0-day}），\textbf{误报率低至 1.7\%}，揭示了“隐藏≠安全”的深层安全风险。

延续Web访问控制方向，\textbf{MOCGuard} (2024)~\cite{MOCGuard}进一步聚焦于Java Web应用中的所有权校验问题。其将数据库中的\textbf{用户-数据关系建模}为分析核心，并结合跨层静态追踪（Java逻辑与SQL访问）自动识别所有权检查是否缺失，形成可适用于大规模工业项目的高精度批量检测工具。该方法在Sun等人[31]提出的路径建模思路基础上，进一步拓展至所有权维度与跨语言场景，展示了更强的实用性和通用性。

随着小程序生态的兴起，新型权限问题也在不断涌现。Zhao等人 (2023)~\cite{10.1145/3605762.3624433}关注\textbf{插件通信过程中签名校验机制缺失}的问题，指出平台虽提供了签名集成方案，但并没有强制要求程序实现，导致开发者常忽视签名校验，从而造成通信被拦截、篡改、重放，进而导致未授权访问。该工作强调平台应强化内置的默认安全机制，以降低因开发者失误导致的系统性漏洞风险。

Yang等人 (2022)\cite{10.1145/3548606.3560597}定义并系统化分析了\textbf{“跨小程序请求伪造”}（CMRF）攻击问题。该研究开发了CMRFSCANNER，对数百万微信与百度小程序进行静态分析，发现绝大多数小程序在处理跨应用请求时未对发送方appId进行校验，导致发送者可以伪装身份越权访问敏感操作，导致隐私数据泄露、越权访问等。该工作强调了小程序开发中安全意识普遍不足的问题，也提示平台方应提供更清晰的API安全指引。  

"""

_7_IMPROPER_DATA = r"""

\section{权限检查不当}

尽管许多系统已经实现了安全检查机制，用以防止未授权访问或不当操作，但这些检查本身并非总是可靠。即使形式上存在安全检查，若其逻辑设计不当、上下文理解错误或语义表达不一致，也依然可能导致安全缺陷，这类问题被统称为“检查不当”。

针对 TOCTOU 漏洞的检测，Wang等人 (2018)提出\textbf{LRC缺陷检测框架}~\cite{10.1145/3243734.3243844}，其核心创新在于通过追踪条件分支中错误码（如 -EINVAL）的传播路径，定位安全关键检查点；再逆向分析检查点变量的数据流，识别其依赖的源头（如用户输入）。通过构建\textbf{“检查-使用”执行链}，检测变量在后续使用前是否被二次修改（如线程共享更新），若修改后缺乏重新验证则判定为LRC漏洞。该方法首次系统化解决内核重检缺失问题。

除操作系统外，检查不当问题在上层应用系统中同样广泛存在。例如，针对内存安全语言（如 Go）中复杂的错误处理逻辑，Anwar等 (2025)提出 \textbf{GOSONAR} 工具\cite{GoSonar}，通过提取函数控制流图中的\textbf{路径切片}、聚焦错误返回处理流程，并利用最长公共子序列算法\textbf{匹配相似路径}，从中归纳出函数的错误返回模式。该方法结合 Wilson Score 区间估计置信度，有效定位高频一致的逻辑检查缺陷。

在 Web 应用中，对象级访问控制（BOLA）检测则代表另一类复杂的检查不当问题。Huang等人 (2024)设计了 \textbf{BolaRay} 系统~\cite{10.1145/3658644.3690227}，首创性地在无需人工标注的前提下，自动推理数据库中对象与用户之间的权限关系模型（如 ownership、membership、hierarchical 和 status），结合\textbf{静态代码分析}和 \textbf{SQL 查询建模}，有效识别因授权判断逻辑不严谨而导致的对象级权限绕过，大幅领先于只能分析ownership单一模型的旧方法。

% TODO: 视情况挪到 MPC 里
而在无源代码的黑盒服务场景中，Zuo等 (2017)~\cite{10.1145/3133956.3134089}提出的 \textbf{AUTHSCOPE} 工具通过对多用户请求流量进行\textbf{差分分析}，替换身份字段（如 Cookie）并比对响应行为，从而发现后端缺乏精确授权判断的漏洞。该方法突破了传统依赖源代码的局限，为大规模网络服务中检查缺失与检查不当问题的发现提供了新思路。

在移动平台，残留 API 可能未正确定义权限保护，从而引发访问控制缺陷漏洞。为此，El-Rewini 与 Aafer (2021)针对定制化 Android ROM 中的残留 API 安全隐患提出 \textbf{$ReM^3$ 框架}~\cite{10.1145/3460120.3485374}，通过结合应用层与框架层\textbf{静态分析}，准确识别未在当前系统使用但仍保留于代码中的 OEM 私有 API 。

随着系统形态的多样化，权限检查从传统操作系统向 Web 应用、小程序及区块链智能合约等新兴平台不断扩展，而检查不当问题也呈现出更加复杂与隐蔽的形式，研究者纷纷提出针对性的检测方法以应对新的挑战。为应对小程序中滥用权限请求带来的隐私风险，Wang 等人(2024)~\cite{10.1145/3691620.3695534}提出了 \textbf{MiniChecker} 工具。该工具通过\textbf{构建小程序通用函数调用图}，结合\textbf{事件驱动的行为传播算法}，精确识别权限请求相关的调用序列，并引入三阶段动作模型（事前、事中、事后）提取行为特征，实现对首页弹窗、覆盖弹窗等五类权限滥用行为的自动化分类识别。MiniChecker 在大规模真实小程序测试中表现出优异的检测精度与召回率，揭示了当前小程序权限设计中的固有漏洞。

针对小程序中的跨页面请求伪造（MiniCPRF）漏洞，Zhang等人 (2024)~\cite{10.1145/3658644.3670294}提出 \textbf{MiniCAT} 分析框架。该框架首先爬取小程序，然后以页面跳转 API 作为汇点，结合\textbf{逆向污点分析}，反向追踪找到事件处理函数和前端 WXML 属性，进而检查调用链中的用户状态校验缺陷，综合评估 CPRF 风险

在智能合约场景中，访问控制不当问题同样广泛存在，具体表现为在实现预定的业务规则、状态转换逻辑或访问控制策略时出现偏差。这些缺陷可能导致合约的执行流程与预期不符，关键状态遭到未授权修改，用户权限被非法绕过，或者链上资产发生非授权转移。针对跨链合约交互中频繁出现的行为语义错配问题，\textbf{HighGuard}引入\textbf{动态条件响应图（DCR）}(2024)~\cite{10.1145/3691620.3695356}作为形式化规范，实时监控检测交易序列中的违规行为。

\textbf{FuzzDelSol}(2023)~\cite{10.1145/3576915.3623178}是一套专门针对Solana智能合约的\textbf{模糊测试}框架，聚焦签名者权限配置及业务逻辑相关缺陷。该框架通过系统化状态空间探索，成功揭露多种实际存在的权限校验错误的逻辑漏洞，为Solana生态的智能合约安全提供了实用检测手段。\textbf{ItyFuzz}(2023)~\cite{10.1145/3597926.3598059}基于\textbf{快照技术}实现高效智能合约\textbf{模糊测试}，能够快速回滚合约状态，深入探索状态空间，显著提升访问控制错误的发现能力，为智能合约安全审计提供了一种高效新途径。

由于区块链交易全公开的特点，从已发生的攻击事件中学习并构建防御机制也是一种重要的研究思路。Zhang等人 (2023)~\cite{10.5555/3620237.3620336}通过分析已知的链上攻击事件，\textbf{自动合成}用于\textbf{反制}这些特定攻击的智能合约，其分析过程也间接揭示了原始合约中存在的各类逻辑缺陷，包括权限控制和状态管理等方面的问题。

重入漏洞是智能合约安全领域中一种具有代表性且危害性极高的时序安全问题。正常的用户在调用合约函数后，交易完成前，没有权限再次访问相同合约的函数。如果对这种权限检查不当，就会导致重入漏洞。攻击者通常会利用重入路径重复执行如提款等危险操作，从而导致资金被盗。针对这类具有明确模式的漏洞，Cai等 (2025)~\cite{10926491} 提出了一种基于合约标准（Contract Standards）的\textbf{规则化检测方法}。该方法通过静态分析 Solidity 智能合约代码，专门识别和报告潜在的重入风险点。

近年来，随着 LLM 的发展，研究者逐步探索其在智能合约逻辑漏洞检测中的潜力。早期的研究尝试直接利用 LLM 的自然语言理解与代码生成能力，给予提示工程对智能合约代码进行检测。例如，Chen 等（2025）~\cite{chen2025chatgpt} 系统评估了 \textbf{ChatGPT} 在智能合约漏洞检测任务中的表现。该研究聚焦 \textbf{DASP Top10}~\cite{dasp2025}中的前九类逻辑漏洞（如可重入调用、访问控制、未检查返回值等），DASP(Decentralized Application Security Project)是国家计算中心小组 (NCC) 提出的的开放协作项目，旨在共同发现安全社区内的智能合约漏洞。实验证明 ChatGPT 在检测效率方面具有优势，但在准确性和稳定性上仍存在明显不足，特别是对于复杂场景与边界条件的处理。

为了克服通用大模型对智能合约语义理解不足的问题，后续工作尝试将 LLM 与程序分析技术结合。
\qquad \textbf{GPTScan}(2024)~\cite{sun2024gptscan} 是首个将 \textbf{LLM} 与\textbf{静态分析}协同用于智能合约逻辑漏洞检测的系统。GPTScan 首先将漏洞类型分解为具体“场景-属性”对，使 GPT 能基于语义提示识别潜在风险函数；然后结合程序分析方法验证漏洞存在性，显著降低误报率。该方法覆盖了十种常见逻辑漏洞，证明 LLM 在结构化知识辅助下具备较强的匹配能力。

进一步地，\textbf{PropertyGPT}(2025)~\cite{liu2024propertygpt} 提出将\textbf{检索增强生成（RAG）}机制引入漏洞检测任务，引导模型生成满足\textbf{形式化验证}需求的属性，从而实现在形式验证层面的漏洞发现。该方法将检测能力扩展至13类逻辑漏洞，性能超越 GPTScan。然而， PropertyGPT 仍依赖专家提供的高质量示例，在泛化性上存在一定局限。

通过训练和微调机制优化 LLM 在漏洞检测任务中的表现也是一个研究重点。\textbf{SmartInv}(2024)~\cite{wang2024smartinv} 提出了一种新的\textbf{微调}和\textbf{提示} LLM 的策略，即\textbf{层级思维}（Tier of Thought, ToT），使用先前较简单的层级的答案来指导后续更具挑战性的层级的答案生成，用于 LLM 在智能合约的多种模态之间进行推理并生成不变量。通过识别任何违反这些不变量的异常执行路径，SmartInv 能够有效指示潜在的业务逻辑漏洞或权限控制缺陷。

\textbf{Smart-LLaMA} (2025)~\cite{yu2024smart} 则探索直接训练和微调 LLM 进行漏洞发现和解释。研究人员提出了一种\textbf{两阶段后训练策略}，先使用大规模智能合约数据进行领域预训练，再通过任务微调提升检测与解释能力。Smart-LLaMA 聚焦于四类典型高危漏洞（重入、时间依赖、整数溢出与委托调用），在检测准确性和解释性方面均超越传统方法和基础预训练模型。

\textbf{iAudit} (2025)~\cite{ma2024combining} 从另一个角度出发，结合 LLM 智能体进行漏洞检测与解释。构建了 Detector、Reasoner、Ranker 和 Critic 四类代理，通过\textbf{微调}与\textbf{多轮推理和决策投票机制}，进行智能合约的逻辑漏洞检测，并输出最合适的漏洞成因解释。相比其他方法，iAudit 更强调实际项目场景中的语义理解与逻辑推演，适用于对解释性要求较高的合约安全审计任务。

此外，针对智能合约中的可重入漏洞的检测，\textbf{AdvSCanner}(2024)~\cite{wu2024advscanner} 提出将 LLM 与静态分析结合，\textbf{自动生成可利用重入漏洞}的对抗性智能合约。采用静态分析来确定合适的攻击流并收集必要的漏洞信息，用于构建信息提示。随后，利用\textbf{思维链 （CoT）} 提示策略指导 LLM 生成对抗性合约，并引入链式提示和自我反思机制，以缓解大模型的幻觉问题，提升漏洞利用的可靠性与效果。

除智能合约场景外，LLM 与静态分析的融合也在传统软件的逻辑漏洞检测中展现出强大潜力，特别是在路径遍历和注入类漏洞（如 XSS、命令注入）检测方面。这类漏洞通常依赖复杂的数据流与控制流上下文，传统静态分析往往难以准确建模，而 LLM 的语义理解能力恰好弥补了这一不足。

\textbf{IRIS}(2025)~\cite{li2025iris}  和 Artemis(2025)~\cite{ji2025artemis} 创新性地利用 LLM 语义理解能力筛选潜在漏洞函数，以提升静态漏洞检测的精度和效率。其中，IRIS 进一步使用 LLM 提供切片来消除误报。在漏洞类别上，\textbf{Artemis} 主要聚焦于服务端请求伪造（SSRF） 漏洞，而 IRIS 则覆盖更广，关注路径遍历、命令注入、跨站脚本（XSS）和代码注入四类逻辑漏洞。

然而，由于 IRIS 和 Artemis 仍然依赖于现有的专家制作的检测模式，在泛化性上具有一定局限。为此，\textbf{MoCQ} (2025)~\cite{li2025automated} 提出了一种神经符号融合框架，利用 LLM 从代码中自动\textbf{提取漏洞模式}并生成\textbf{静态分析查询}，提升了对注入类漏洞（如 SQLi 和 XSS）在 PHP 和 JavaScript 等动态语言中的检测能力。\textbf{LLMSA} (2024)~\cite{wang2024llmsa} 则从另一个角度出发，使用 LLM 将\textbf{漏洞分析问题分解}为较小代码片段上的几个简单的句法或语义属性，以简化静态分析任务。LLMSA 可以有效支持如绝对路径遍历、XSS 等污点传播相关漏洞的检测，展示出强适应性与解释性。
"""

_8_CONCLUSION_DATA = r"""
本文系统梳理了逻辑漏洞挖掘领域的研究进展，重点关注竞争型漏洞、越权访问、校验不一致性、权限检查缺失、权限检查不当及代码设计与实现差异六类常见逻辑漏洞，涵盖了Web应用、移动应用、操作系统、Web3等多种场景。传统检测方法主要包括静态分析与动态分析，尽管在一定程度上具备实用价值，但仍面临诸如执行上下文理解不足、精确路径建模能力有限等瓶颈。

近年来，随着LLM快速发展，研究人员探索将LLM的语义理解能力逐步用于逻辑漏洞检测。从辅助函数筛选、到切片生成、再到规则抽象与语义分解，LLM 与传统工具的耦合正不断深入和多样，推动逻辑漏洞检测的自动化和智能化发展。

然而，尽管这些方法覆盖了多种常见逻辑漏洞，并在泛化性、可解释性或验证机制上各有创新，但整体上仍未对不同漏洞类型采取精细化、差异化的检测机制。未来，亟需进一步探索更具针对性的优化策略，以提升逻辑检测的准确性与覆盖率，从而助力构建更加健壮、可信的安全系统。
"""

TEX_SRC_DATA = "\n".join(
    [
        _2_RACE_DATA,
        _3_ESCALATE_DATA,
        _4_DESIGN_IMPL_DIFF_DATA,
        _5_INCONSISTENT_DATA,
        _6_MPC_DATA,
        _7_IMPROPER_DATA,
        _8_CONCLUSION_DATA,
    ]
)


def load_input_table_df():
    df = pd.read_excel(INPUT_XLSX, sheet_name="Sheet1")

    # Fix headers
    df.rename(
        columns={
            "漏洞类型": "竞争型漏洞",
            "Unnamed: 3": "越权行为",
            "Unnamed: 4": "不一致性",
            "Unnamed: 5": "权限检查缺失",
            "Unnamed: 6": "权限检查不当",
            "Unnamed: 7": "代码设计与现实差异",
            "方法": "静态",
            "Unnamed: 9": "动态",
            "Unnamed: 10": "LLM",
        },
        inplace=True,
    )
    df["应用场景"] = df["应用场景"].ffill()
    df.drop(index=0, inplace=True)  # Remove the first row which is a header row
    return df


"""

应用场景    论文名称(工具名或作者名) 竞争型漏洞 越权行为 不一致性 权限检查缺失 权限检查不当 代码设计与现实差异   静态   动态  LLM

"""


def sanitize_tool_name(tool_name):
    # Remove any content in square brackets and strip whitespace
    tool_name = re.sub(r"\[[0-9]+\]", "", tool_name).strip()
    if "et.al" in tool_name:
        return None
    if len(tool_name.split()) > 1:
        # If the tool name contains multiple words, return None
        return None
    return tool_name


def preprocess_tex_paragraphs():
    """
    Preprocess the LaTeX paragraphs to filter out those that do not contain citations.
    """
    global TEX_PARAGRAPHS
    lines = TEX_SRC_DATA.split("\n")
    lines = map(lambda x: x.strip(), lines)
    TEX_PARAGRAPHS = "\n".join(lines).split("\n\n")
    TEX_PARAGRAPHS = filter(
        lambda x: r"\cite" in x and not x.startswith("%"), TEX_PARAGRAPHS
    )
    TEX_PARAGRAPHS = list(TEX_PARAGRAPHS)


class CiteMeta(BaseModel):
    """
    根据给定的上下文，找到 \\cite{} 的 bibtex 标签
    """

    bibtex_key: str = Field(description="BibTeX key extracted from the LaTeX citation.")


def dump_df_to_latex(df: pd.DataFrame):
    lines = []
    DING = r"\ding{72}"
    CHECKMARK = r"\checkmark"
    for i, row in df.iterrows():
        if row["应用场景"] is None:
            continue
        line = "&".join(
            [
                " ",
                row["论文名称(工具名或作者名)"],
                DING if row["竞争型漏洞"] == "x" else " ",
                DING if row["越权行为"] == "x" else " ",
                DING if row["代码设计与现实差异"] == "x" else " ",
                DING if row["不一致性"] == "x" else " ",
                DING if row["权限检查缺失"] == "x" else " ",
                DING if row["权限检查不当"] == "x" else " ",
                " ",
                CHECKMARK if row["静态"] == "x" else " ",
                CHECKMARK if row["动态"] == "x" else " ",
                CHECKMARK if row["LLM"] == "x" else " ",
            ]
        )
        lines.append(f"{line} \\\\")
    return "\n".join(lines)


DEFAULT_MODEL = "gpt-4.1-mini"
llm = init_chat_model(
    DEFAULT_MODEL,
    model_provider="openai",
)
parser = PydanticOutputParser(pydantic_object=CiteMeta)
prompt = ChatPromptTemplate.from_template(
    template="根据给定的上下文，找到 \\cite{{}} 的 bibtex 标签。上下文：{context}。你应该按以下 pydantic 模型格式返回结果：{format_instructions}",
    partial_variables={
        "format_instructions": parser.get_format_instructions(),
    },
)

chain = prompt | llm | parser


def main():
    preprocess_tex_paragraphs()
    df = load_input_table_df()

    for idx, row in df.iterrows():
        if row["应用场景"] is None:
            continue
        tool_name = sanitize_tool_name(row["论文名称(工具名或作者名)"])
        if tool_name is None:
            continue
        todo_paragraphs = [p for p in TEX_PARAGRAPHS if tool_name.upper() in p.upper()]

        if len(todo_paragraphs) == 0:
            print(
                f"Warning: Found {len(todo_paragraphs)} paragraphs for tool '{tool_name}' in the LaTeX source."
            )
            continue

        p = "".join(todo_paragraphs)

        if len(todo_paragraphs) == 1:

            bibtex_keys = re.findall(r"\\cite\{([^}]+)\}", p)
            if bibtex_keys.__len__() != 1:
                print(
                    f"Warning: Found {bibtex_keys.__len__()} bibtex keys for tool '{tool_name}' in the LaTeX source."
                )
            else:
                bibtex_key = bibtex_keys[0]
        if not (len(todo_paragraphs) == len(bibtex_keys) == 1):
            # Use LLM to find the bibtex key
            print(f"Using LLM to find bibtex key for tool '{tool_name}'")
            context = p
            result: CiteMeta = chain.invoke({"context": context})
            bibtex_key = result.bibtex_key

        df.loc[idx, "论文名称(工具名或作者名)"] = tool_name + f"~\\cite{{{bibtex_key}}}"

    with open(OUTPUT_CSV, "w", encoding="utf-8") as f:
        f.write(dump_df_to_latex(df))


if __name__ == "__main__":
    main()
