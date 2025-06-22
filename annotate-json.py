"""
Use this script to automate text annotation tasks
"""

import asyncio
import os
from typing import Generator, List, Literal, Optional

from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

DEFAULT_MODEL = "gpt-4.1-mini"

DATA = """

## Mobile
#### Kobold: Evaluating Decentralized Access Control for Remote NSXPC Methods on iOS

Wang等人 [13] 针对AppleOS中存在的“混淆代理”（Confused Deputy）问题，即低权限程序通过IPC请求诱使高权限系统服务滥用其权限，提出了一个名为ISERVICE的系统性静态分析方法来自动检测此类漏洞并评估其影响。由于AppleOS系统服务的闭源特性和复杂性，识别此类漏洞极具挑战。ISERVICE的核心思想是关注系统服务执行的、一旦被滥用就可能危害系统的敏感操作，并检查IPC输入在调用这些操作前是否经过了恰当的验证。该方法首先通过自顶向下的类型传播解析包括Objective-C消息在内的函数调用以生成调用图，然后基于敏感操作对调用图进行剪枝，接着通过面向敏感操作的数据流分析（在代码属性图上进行）来识别IPC输入与敏感操作关键参数间的数据依赖关系，从而提取输入校验措施。最后，ISERVICE评估这些保护措施的有效性，并根据敏感操作被滥用的严重程度以及IPC输入对其的控制程度来对混淆代理漏洞进行评分和报告。通过对四个macOS版本的439个系统服务进行分析，ISERVICE成功发现了11个可利用的混淆代理漏洞（其中5个为0-day漏洞，均已获CVE编号并被苹果修复），这些漏洞可导致任意文件覆写和命令执行等特权升级行为。

#### iService: Detecting and Evaluating the Impact of Confused Deputy Problem in AppleOS

Deshotels等人 [14] 针对iOS系统中第三方应用可能通过与系统守护进程进行NSXPC（一种面向对象的IPC机制）通信，从而间接访问敏感资源并引发“混淆代理”漏洞的问题，提出了Kobold框架。由于iOS的闭源特性，IPC接口及其访问控制策略难以获知。Kobold结合静态与动态分析：首先，通过分析App Store应用来枚举第三方应用可获得的公开及“半私有”权限（entitlements）；接着，静态分析iOS固件以提取NSXPC的mach端口、方法名和参数类型；然后，动态探测这些接口的实际可访问性，并利用错误信息和完成处理器（completion handlers）反馈来近似推断访问控制策略（如权限需求）。通过对iOS 9、10和11版本的分析，Kobold发现了多个NSXPC服务的混淆代理漏洞和守护进程崩溃，这些漏洞可导致未经授权激活麦克风、禁止所有网站访问以及泄露iOS文件提供者（File Providers）中的私有数据等严重后果，其中部分漏洞已获得CVE编号。


#### 2. Kratos: discovering inconsistent security policy enforcement in the android framework(NDSS 16)

针对安卓框架中存在的安全策略执行不一致问题，Shao等人提出了Kratos ，这是一个静态分析工具，旨在系统性地发现那些允许权限不足的第三方应用访问敏感资源的安全漏洞 。Kratos通过构建精确的安卓框架调用图，标注图中各节点所执行的安全检查（如权限检查、UID检查等），并通过成对比较不同服务接口的子调用图，来识别那些能访问到相同敏感方法但安全检查策略不一致的路径 。该工具在分析AOSP（安卓开源项目）及厂商定制的安卓版本时，克服了IPC处理、私有服务类识别和大规模代码分析等挑战 。通过对包括安卓4.4至M预览版以及两款定制版在内的六个安卓版本的分析，Kratos发现了至少14个可利用的不一致安全执行案例，这些案例分布在短信、Wi-Fi等重要服务中，可能导致权限提升、拒绝服务或软重启等严重后果 。值得注意的是，其中许多漏洞与通过Java反射机制访问的隐藏接口有关 

#### 3. Harvesting inconsistent security configurations in custom android roms via differential analysis(usenix security 16) 

针对安卓定制化过程中（如厂商、运营商修改）可能引入的安全配置不一致问题，Aafer等人 [2] 提出了DroidDiff工具。该研究首先系统性地识别了安卓各层中可能在定制过程中被修改的关键安全配置特征（如权限保护级别、GID映射、受保护广播、组件可见性和组件保护配置） 。随后，DroidDiff从收集的591个定制安卓ROM中提取这些特征值 ，并运用五种差分分析算法（跨厂商、跨型号、跨区域、跨运营商、跨版本）来检测这些特征配置的不一致性 。研究结果表明，安全配置的不一致在定制ROM中普遍存在 ，例如权限保护级别被降低、受保护广播定义被移除、组件保护被削弱等。通过在真实设备上进行攻击验证，研究者证实了这些不一致性确实能够导致实际的安全风险，如未经授权触发紧急广播、无需用户确认恢复出厂设置以及伪造短信等 。

#### AuthScope: Towards Automatic Discovery of Vulnerable Authorizations in Online Services(CCS’17)

为了自动发现网络服务中存在的授权漏洞，Zuo等人 [1] 开发了AUTHSCOPE工具，该工具通过分析移动应用与其后端服务器的交互流量来识别服务器端的访问控制缺陷 [cite: 3]。其核心思想是利用差分流量分析技术：首先，通过一个自适应的应用活动动态探索器驱动应用自动登录（特别针对使用Facebook登录的应用）以获取两个不同用户（如Alice和Bob）的认证后请求及响应消息 [cite: 6, 123, 216]；接着，对比分析这两个用户的请求，识别出用户相关的、可枚举的字段（如用户ID、邮箱地址、Facebook ID等） [cite: 4, 129, 258, 274, 277]；然后，将Alice请求中的这些可枚举字段替换为Bob对应的值，并观察服务器响应 [cite: 4, 282]；如果服务器返回了Bob的私有数据，则判定存在授权漏洞 [cite: 102, 286]。通过对4838个热门安卓应用的测试，AUTHSCOPE发现了306个应用对应的在线服务中存在597个0-day易受攻击的授权实现，这些漏洞主要源于服务器错误地使用可预测ID或用户公开信息（如邮箱）进行授权，而未充分校验安全令牌 [cite: 7, 39, 40]。

#### 4. AceDroid: normalizing diverse android access control checks for inconsistency detection(NDSS 18)

针对安卓框架中访问控制检查多样性（尤其在厂商定制ROM中）导致不一致性检测困难的问题，Aafer等人 [2] 提出了AceDroid分析框架。该框架通过路径敏感的方式对访问控制检查进行建模，并将不同形式但语义等价的检查（如基于UID、包名、签名或特定系统属性的检查）规范化为统一的范式，该范式区分为应用层面（权限、所有权、状态）和用户层面（用户特权、所有权、状态、限制）。AceDroid能够处理检查间的复杂逻辑关系（如与、或），为每个资源访问路径生成一个简洁精确的规范化安全条件。通过对12个（包括三星、索尼、HTC和LG的定制版本以及不同安卓版本）ROM镜像进行分析，AceDroid有效地检测出大量由厂商定制引入的不一致性，并显著减少了误报。研究者利用这些发现成功实施了包括按键记录、发送付费短信、绕过用户限制及拒绝服务在内的高危攻击。

#### FIRMSCOPE: Automatic Uncovering of Privilege-Escalation Vulnerabilities in Pre-Installed Apps in Android Firmware(usenix20)

针对安卓固件中预装应用（通常具有高权限且用户无法卸载）可能存在的权限提升漏洞，Elsabagh等人 [1] 开发了 FIRMSCOPE 系统 [cite: 1, 4, 7]。该系统利用一种新颖的静态污点分析技术，能够进行上下文敏感、流敏感、字段敏感以及部分对象敏感的分析，以自动发现预装应用中可被外部调用（如被第三方应用或远程方调用）的提权漏洞 [cite: 7, 28]。FIRMSCOPE 首先对固件进行预处理，包括解包、提取和反汇编预装应用，然后构建过程间控制流图（ICFGs）和数据流图（IDFGs），最后执行定制的污点分析来识别漏洞路径 [cite: 131, 133, 163]。通过对来自100多家安卓供应商的2017个固件镜像（版本从v4.0到v9.0）中的331342个预装应用进行扫描，FIRMSCOPE发现了850个独特的权限提升漏洞（共计3483个实例），这些漏洞涉及命令注入、任意应用安装卸载、代码注入、恢复出厂设置、短信操控以及屏幕和音频录制等 [cite: 9, 10, 35, 37, 38]。该研究强调，尽管这些预装应用被认为是安全的，但它们中存在的漏洞对用户构成了严重的安全威胁 [cite: 5, 6]。

> 是系统用户本来才能做的，现在普通用户也可以做了

#### Dissecting Residual APIs in Custom Android ROMs(CCS21). waterloo

El-Rewini和Aafer [1] 针对定制安卓ROM中存在的残留API（Residual APIs）——即在特定设备上未使用但可能存在于旧版本或其他型号中的OEM私有API——进行了首次大规模安全调查 。他们认为，由于这些残留API被视为非必要功能，在集成和维护过程中容易被忽视，从而可能引入访问控制漏洞 。为验证此假设，研究者提出了一套名为ReM³的分析技术，该技术结合应用层和框架层程序分析来识别潜在的残留API，并通过历史和跨模型使用模式确认其实际残留状态 。随后，ReM³对确认的残留API进行静态分析，以检测因未能适应安卓访问控制机制演进而导致的安全缺陷，例如使用未定义权限等不健全的安全特性或过时的访问控制策略 。通过分析来自三星、LG等7家厂商的628个ROM，研究发现残留API普遍存在，部分型号中占比高达42% ；更重要的是，约23%的残留API保护薄弱，并成功利用了其中8个实例（如在三星和LG设备上实现按键记录器），导致了严重的安全漏洞，获得了多个CVE编号 


#### Android SmartTVs Vulnerability Discovery via Log-Guided Fuzzing(Usenix 21) waterloo - FUZZ

针对安卓智能电视中因厂商定制而引入的安全风险，特别是那些涉及原生代码且可能仅表现为物理层面（视觉或听觉）异常的漏洞，Aafer等人 [1] 提出了一种新颖的日志引导模糊测试方法。该方法首先通过静态分析定位智能电视中的定制API（包括Java层和通过二进制分析恢复的原生层接口）作为模糊测试目标 ；接着，在动态模糊测试过程中，系统通过分析安卓执行日志来实时推断输入规范（如参数的有效值、范围或格式），这一过程利用了预先训练的分类器来识别和解析日志中的输入验证信息 。此外，该方案引入了一个外部观察器，通过HDMI捕捉并对比测试前后电视的音视频输出，以检测物理层面的异常 。通过对11款安卓电视盒进行测试，该方法发现了37个独立漏洞，包括可导致关键启动环境设置损坏、敏感数据泄露等高危网络威胁，以及内存损坏和视觉/听觉干扰等问题 。

#### Watch Out for Race Condition Attacks When Using Android External Storage(CCS 22) 信工大（统计测量）

为全面了解安卓外部存储上因文件操作不当引入的竞争条件攻击现状，Du等人 [1] 提出了名为RECAST的分析引擎 [cite: 8]。该引擎的客户端利用`android.os.FileObserver`收集外部存储上的文件操作事件（包括操作类型、发生时间、文件路径等）[cite: 68, 153]，服务器端则对这些事件进行处理，包括过滤、关联、排序，并推断文件操作流程和命名模式，以识别潜在的竞争条件 [cite: 155, 157, 158, 159, 70]。通过对10位志愿者连续10天手机使用数据（共计5359339个文件操作事件，涉及105963个文件）的分析 [cite: 9, 74]，研究发现存在大量（1977种）独特的文件操作模式 [cite: 10]，并且在这些模式中，可供恶意应用发起攻击的时间窗口普遍存在 [cite: 11]。手动验证表明，94.26%的抽样测试文件易受此类攻击 [cite: 11, 79]。该研究强调，尽管安卓10引入了分区存储，但由于安卓版本碎片化及`MANAGE_EXTERNAL_STORAGE`权限的存在，外部存储的竞争条件攻击仍是一个不容忽视的问题 [cite: 4, 5, 31, 36, 37]。

#### PredRacer: Predictively Detecting Data Races in Android Applications (SANER24) 东南

针对安卓应用中因其复杂的混合并发模型（多线程与异步消息传递）而频发的数据竞争问题，Guo等人提出了PredRacer，一种预测性的数据竞争检测方法 [cite: 3, 4, 5, 7]。该方法首先通过插桩捕获安卓应用的执行轨迹，然后基于偏序关系对轨迹中的事件进行重排序，以生成包含潜在数据竞争的事件序列，并最终检查这些序列的可行性 [cite: 8, 9, 31, 32, 33]。PredRacer结合了安卓并发模型特有的“happens-before”关系来扩大搜索范围并减少误报，同时采用线程化技术处理单线程上下文中的回调事件间数据竞争 [cite: 10, 34]。在BenchERoid数据集和20个开源安卓应用的评估中，PredRacer在精确率、召回率和F1得分上均优于现有技术（如ER Catcher, nAdroid, EventRacer），并通过对300个实际应用的测试验证了其效率和可扩展性 [cite: 11, 12, 13, 36, 37, 38]。

#### Identity Confusion in WebView-based Mobile App-in-app Ecosystems (USENIX 22) 复旦

针对日益流行的基于WebView的移动“应用中应用”（app-in-app）生态系统，Zhang等人 [1] 首次系统性地研究了其中的“身份混淆”漏洞。该研究指出，超级应用（super-app）在向其承载的子应用（sub-app）授予特权API访问权限时，常依赖网页域名、子应用ID或能力（capability）这三类身份进行校验[cite: 1, 5]. 然而，这些身份校验机制设计不当会导致权限授予范围超出预期，从而产生身份混淆，违背了最小权限原则[cite: 5, 10]. 通过对47个主流超级应用（包括安卓和iOS版本）的分析，研究者发现所有受测应用均存在至少一种身份混淆问题，具体表现为域名混淆（如恶意子应用加载特权域名，或利用渲染与校验间的竞争条件）、应用ID混淆（如特权子应用加载恶意域名）以及能力混淆（如恶意实体窃取或不当获取特权能力）[cite: 13, 14, 52, 56, 59]. 这些漏洞可导致严重后果，例如操纵用户金融账户和安装恶意软件[cite: 15, 73].

#### Uncovering Cross-Context Inconsistent Access Control Enforcement in Android(NDSS22)港理工

Zhou等人 [1] 针对安卓系统中Java层与原生层（Native）之间存在的跨上下文访问控制策略不一致问题进行了首次系统性研究，此类不一致可能被恶意软件利用以绕过权限检查。为自动发现这些漏洞，研究者设计并实现了IAceFinder工具 [cite: 1, 4]。IAceFinder首先分别对安卓框架的Java库（.jar文件）和原生库（.so文件）进行静态分析，构建Java系统服务和原生系统服务的调用图 [cite: 23]。接着，它识别出连接这两个上下文的Java原生接口（JNI），并提取在JNI方法（Java端）和对应的JNI函数（原生端）上实施的访问控制（主要是权限和UID检查） [cite: 29]。通过将这些不同形式的访问控制规范化为统一的特权等级（系统、shell、普通、无），IAceFinder对比JNI方法及其对应JNI函数的特权要求差异，从而发现两类不一致性：类型1不一致是指原生层目标接口的访问控制比Java层代理接口更宽松，类型2不一致则相反 [cite: 157, 164]。通过对14个开源安卓ROM（包括官方AOSP和LineageOS等第三方ROM）的应用测试，IAceFinder成功发现了23个可被利用的跨上下文不一致访问控制实施案例，这些漏洞可能导致设备受损或用户隐私泄露 [cite: 5, 6]。

#### Cross Miniapp Request Forgery: Root Causes, Attacks, and Vulnerability Detection(CCS22)俄亥俄州立

针对小程序（miniapp）生态中跨应用通信的安全问题，Yang等人 [1] 首次研究并定义了“跨小程序请求伪造”（Cross-Miniapp Request Forgery, CMRF）攻击。此类攻击源于接收方小程序在处理来自其他小程序（发送方）的请求时，未能检验发送方的`appId`（由超级应用分配的唯一全局标识符） [cite: 4, 41]。研究者开发了静态分析工具CMRFSCANNER，通过分析小程序代码的抽象语法树（AST）来检测是否存在`appId`校验缺失 [cite: 5, 157]。在对2,571,490个微信小程序和148,512个百度小程序的测试中，分别有52,394个和494个小程序涉及跨应用通信 [cite: 6]；在这些进行跨应用通信的小程序中，高达95.97%的微信小程序和99.80%的百度小程序缺乏对发送方`appId`的校验，表明开发者普遍缺乏对此风险的认知 [cite: 7]。进一步的影响评估发现，这些存在漏洞的小程序中有相当一部分（微信55.05%，百度7.09%）可能导致特权数据访问、信息泄露、优惠滥用乃至免费购物等严重安全后果 [cite: 8]。

#### Potential Risks Arising from the Absence of Signature Verification in Miniapp Plugins(SaTS23)

Zhao等人 [10] 探讨了小程序（miniapp）插件中缺少签名校验机制所引发的潜在安全风险。研究指出，小程序插件作为增强小程序功能的模块化组件，其与小程序间的通信安全至关重要 [cite: 3, 22, 43, 45]。尽管平台方（如腾讯）提供了签名集成指南，旨在通过对请求中的APPID、随机串（NONCESTR）、时间戳（TIMESTAMP）和插件令牌（TOKEN）进行排序、拼接和哈希（如SHA1）来生成和验证签名，从而确保通信的真实性和完整性，但此校验并非预置功能，可能被经验不足的开发者忽略 [cite: 5, 30, 31, 81, 82, 87, 88, 91, 92, 93, 96, 99, 100]。这种缺失会导致严重的安全漏洞，例如攻击者可以拦截并篡改小程序与插件间的通信数据（如修改支付金额），或重放指令，进行数据操纵攻击和指令重执行攻击，最终可能导致用户财产损失或服务被滥用 [cite: 6, 32, 33, 35, 112, 126, 131, 133, 140, 142]。该文强调了强制性签名校验在维护小程序生态系统安全方面的必要性 [cite: 39, 157]。

#### TrustedDomain Compromise Attack in App-in-app Ecosystems(SaTS23)

Zhang等人 [14] 针对应用内应用（app-in-app）生态系统中基于域名白名单的安全机制进行了研究，并提出了一种名为“可信域名泄露攻击”（TrustedDomain Compromise Attack, TDCAttack）的新型攻击方式 [cite: 4, 59]。该研究指出，超级应用（super-app）通常采用类似内容安全策略（CSP）的域名白名单来限制小程序（mini-app）加载不安全的网络内容 [cite: 2, 19, 20]。然而，这种机制假设白名单内的所有域名资产都是可信的，这在实践中并不可靠 [cite: 3, 25]。攻击者可以通过操纵白名单内不安全的域名（如子域名接管、过期域名）或域名下的不安全资产（如存在XSS漏洞、开放重定向的页面）来绕过白名单校验，进而发起钓鱼攻击或滥用超级应用提供的运行时API [cite: 4, 29, 30, 32, 33]。为了评估此风险，研究者开发了一个自动化分析框架，首先从11838个小程序（包括微信、支付宝和百度平台）的源码中提取和扩展域名白名单，然后评估这些域名资产的安全性，最终通过模板化动态测试验证漏洞的可利用性 [cite: 6, 37, 43, 55, 56, 57]。实验结果显示，主流的应用内应用生态均易受TDCAttack影响，并成功识别了26个可被利用的小程序，证实了此类攻击可导致钓鱼、隐私泄露和权限提升等严重后果 [cite: 7, 8, 58]。

#### Towards a Better Super-App Architecture from a Browser Security Perspective(SaTS23)蚂蚁

Wang等人 [12] 首次从浏览器安全视角对超级应用（super-app）的架构和安全机制进行了研究。研究指出，尽管超级应用广泛采用WebView等浏览器技术来承载小程序（mini-app），从而继承了浏览器的部分威胁模型，但由于小程序在代码分发、执行环境（如共享统一域名）等方面与传统网页应用存在显著差异，导致标准浏览器安全特性（如基于同源策略的资源共享、存储隔离、凭证管理和隐私权限控制）难以直接有效应用于超级应用中 [cite: 6810, 6811, 6834, 6887, 6910, 6911, 6923, 6924, 6927, 6933]。为应对这些挑战，该文提出了一套基于身份实体的安全指南和改进的超级应用架构，其核心在于建立一个不可篡改的“身份中心”来维护各小程序的身份，并通过事件处理器、API处理器以及存储、隐私、资源权限、凭证等安全模块，基于此身份信息实施细粒度的访问控制和隔离，旨在构建更安全的超级应用生态 [cite: 6813, 6839, 6936, 6937, 6942, 6943, 6944, 6949, 6959, 6962, 6966]。

#### MiniCAT: Understanding and Detecting Cross-Page Request Forgery Vulnerabilities in Mini-Programs(CCS24) 山大

Zhang等人 [16] 发现了一种新的小程序漏洞，称为MiniCPRF（小程序跨页面请求伪造），该漏洞源于小程序页面路由和用户状态管理的设计缺陷，如不安全的路由机制、缺乏消息完整性检查以及明文本地存储（例如小程序卡片）[cite: 7354, 7374, 7389]。攻击者可利用小程序的分享转发功能及不安全的本地存储，操纵页面路由URL及其参数，从而执行未授权操作（如免费购物）或窃取敏感信息（如信用卡号）[cite: 7353, 7375, 7376]。为评估此漏洞的影响，研究者开发了自动化分析框架MINICAT，该框架能自动爬取小程序，通过静态分析（特别是逆向污点分析）检测潜在的MiniCPRF漏洞，并检查用户状态校验是否不完整以及页面是否可被分享 [cite: 7355, 7356, 7382, 7594]。通过对41,726个可分析的微信小程序进行大规模评估，MINICAT发现其中32.0%（13,349个）存在MiniCPRF风险，包括一些拥有数百万用户的知名小程序 [cite: 7357, 7385]。研究者已向相关厂商和开发者报告了已验证的漏洞，并获得了三个CNVD漏洞编号 [cite: 7360]。

#### The Dark Forest: Understanding Security Risks of Cross-Party Delegated Resources in Mobile App-in-App Ecosystems (TIFS24)复旦

Zhang等人 [1] 对移动“应用内应用”生态系统中跨方委托资源（Cross-Party Delegated Resources, CPDR）的安全性进行了首次系统性研究。该研究指出，宿主应用（host app）向子应用（sub-app）委托了包括系统能力（如GPS）和用户数据（如电话号码）在内的丰富资源，但相关安全法规在设计与执行上存在模糊和不一致。通过对微信、支付宝等九大应用内应用生态系统的分析，作者总结了11项通用的CPDR安全法规，并发现这些法规普遍未被严格遵守。研究揭示了三种新型攻击途径：伪装攻击（非授权方冒充特权方获取能力）、数据驱动攻击（利用弱数据隔离或输入校验缺失操纵其他子应用）和信道劫持（利用加密缺陷窃取或篡改传输数据）。这些安全弱点可导致子应用后端服务器被操纵、敏感用户数据泄露等严重后果，甚至引发“桶效应”，即一个生态中的漏洞可能危及同一子应用在其他生态中的安全。

#### MiniChecker: Detecting Data Privacy Risk of Abusive Permission Request Behavior in Mini-Programs（ASE '24）

为解决小程序中滥用权限请求引发的数据隐私风险，Wang等人 [1] 开发了自动化工具MiniChecker。该工具首先定义了五种主要的滥用权限请求行为：首页弹窗、覆盖弹窗、骚扰弹窗、重复弹窗和循环弹窗 [cite: 8452, 8502]。MiniChecker通过构建小程序的通用函数调用图（UFCG），解决了传统JavaScript分析工具难以处理小程序特有结构（如预定义对象App/Page、模块引用、模板事件等）的问题 [cite: 8497, 8498, 8600]。随后，它采用行为传播算法标记与权限请求相关的调用序列，并区分主动（事件触发）与被动（生命周期触发）调用 [cite: 8629, 8633, 8634]。最后，MiniChecker结合三阶段模型（事前、事中、事后动作）提取行为特征，对潜在风险进行分类 [cite: 8639, 8642, 8663]。在基准测试中，MiniChecker的精确率和召回率分别达到82.4%和95.3% [cite: 8454]；在对20000个真实小程序的检测中，发现了3866个存在风险的小程序 [cite: 8454, 8519]。该研究揭示了小程序权限机制中固有的设计缺陷，并已将发现反馈给相关平台。


#### Georgiev, Martin, Suman Jana, and Vitaly Shmatikov. "Breaking and fixing origin-based access control in hybrid web/mobile application frameworks." NDSS symposium. Vol. 2014. 2014.

Georgiev 等 [14]针对混合移动应用中，Web层的同源策略与原生操作系统的权限模型之间存在的不兼容的问题进行了研究，揭示了一类名为fracking的通用提权漏洞 。该研究首先对 PhoneGap 等主流混合应用框架开展分析，发现这些框架实现的web层和原生层桥接机制存在缺陷。随后，通过对 7,167 个真实安卓应用的大规模自动化分析，该研究证实隔离在 iframe 中的外部恶意 Web 内容能够利用这些存在缺陷的桥接，绕过同源策略的限制，直接访问用户的通讯录、文件系统等敏感资源 。最后，该研究提出了基于能力令牌的 NOFRAK 防御框架，为每个授权的web域名生成一个不可伪造的能力令牌，并强制在访问本地资源时鉴权，从而修复了该类漏洞。

#### Hernandez, Grant, et al. "{BigMAC}:{Fine-Grained} policy analysis of android firmware." 29th USENIX Security Symposium (USENIX Security 20). 2020.

Hernandez 等[15]针对 Android 系统中强制访问控制（MAC）、自主访问控制（DAC）以及 Linux Capabilities 等多层安全策略之间相互作用所引发的安全问题，提出了 BigMAC 分析框架。该框架通过模拟 Android 系统的启动过程，基于静态固件重建出一个包含所有运行时对象和进程凭证的系统安全快照。在此基础上，框架对多种安全策略进行联合分析，将抽象的安全策略实例化为攻击图，并进一步将攻击图转换为一组 Prolog 事实，从而实现对任意起点与终点之间、满足多重策略约束的攻击路径的高效查询。BigMAC 在对三星和 LG 固件的分析中，发现了多个因策略交互而产生的真实安全隐患，例如非受信任应用能够与内核监控服务或 root 进程通信，凸显出在多种安全策略共存的系统中，开展联合分析的重要性与必要性。

#### [18]Lu, Haoran, et al. "Demystifying resource management risks in emerging mobile app-in-app ecosystems." Proceedings of the 2020 ACM SIGSAC conference on computer and communications Security. 2020.

Lu 等 (2020)[18] 针对应用内应用（app-in-app）生态中，宿主应用 (host app) 作为第三方应用在管理子应用 (sub-app) 访问系统资源时面临的安全挑战进行了首次系统性安全分析。该研究开发了自动化扫描工具 Apinat，通过对 11 个主流的 app-in-app 平台进行分析，识别其中的系统资源暴露、子窗口欺骗、子应用生命周期劫持风险。该分析发现所有被测平台均存在安全风险，并找到了共计52个新漏洞。这些发现凸显了 app-in-app 模式在削弱现有移动操作系统安全模型的同时引入了新的攻击面 ，揭示了由第三方应用构建生态系统在安全管理上的内在局限性。

"""


def get_input_texts() -> Generator[str, None, None]:
    """
    实际获取数据的入口，返回一个生成器，逐条返回数据。
    """
    data = DATA.strip().split("####")
    for x in data:
        x = x.strip()
        if x:
            yield x


# --- 1. 定义期望的输出结构 ---
# 使用 Pydantic 模型来定义你希望 LLM 填充的字段。
# 这就像给 LLM 一个清晰的指令模板。
class AnnotateMeta(BaseModel):
    """从所给的文本提取信息，填充到指定的字段中。"""

    # 使用 Field 来提供更详细的描述，引导 LLM更好地填充内容
    title: str = Field(description="论文标题")
    type: List[
        Literal[
            "竞争型漏洞",
            "越权型漏洞",
            "多条路径检查不一致",
            "权限检查缺失（完全没有检查）",
            "权限检查不当",
            "代码设计与实现存在差异",
        ]
    ] = Field(
        description="分析文章内容，并将其归类为 [竞争型漏洞], [越权型漏洞], [多条路径检查不一致], [权限检查缺失(完全没有检查)], [权限检查不当], [代码设计与实现存在差异] 中的一个或多个，返回所有适用的类型组成的列表"
    )
    scenario: Literal[
        "Web", "Web3", "Mobile(Android)", "Mobile(iOS)", "OS(linux, cloud)"
    ] = Field(
        description="分析文章内容，并将其归类为[Web], [Web3], [Mobile(Android)], [Mobile(iOS)], [OS(linux, cloud)] 中的一个"
    )
    method: List[Literal["静态分析", "动态分析", "LLM"]] = Field(
        description="分析文章内容，并将其归类为[静态分析], [动态分析], [LLM] 中的一个或多个，返回所有适用的类型组成的列表"
    )
    static_techs: List[Literal["控制流", "数据流", "符号执行"]] = Field(
        description="分析文章内容，并将其归类为[控制流], [数据流], [符号执行] 中的一个或多个，返回所有适用的类型组成的列表"
    )
    dynamic_techs: List[Literal["模糊测试", "插桩"]] = Field(
        description="分析文章内容，并将其归类为[模糊测试], [插桩] 中的一个或多个，返回所有适用的类型组成的列表"
    )
    llm_techs: List[Literal["纯 LLM", "LLM + 程序分析"]] = Field(
        description="分析文章内容，并将其归类为[纯 LLM], [LLM + 程序分析] 中的一个或多个，返回所有适用的类型组成的列表"
    )
    short_name: Optional[str] = Field(
        default=None,
        description="如果有的话，提取文章的简称或缩写（如 Kratos, DroidDiff, AuthScope 等）",
    )


# --- 2. 初始化语言模型 ---
# 这里我们使用 OpenAI 的 gpt-4o 模型，你也可以换成其他支持函数调用（Function Calling）或工具使用（Tool Use）的模型。
# temperature=0 表示我们希望模型输出更具确定性、更稳定。
llm = ChatOpenAI(model=DEFAULT_MODEL, temperature=0)

# --- 3. 设置输出解析器 ---
# PydanticOutputParser 会自动根据你的 Pydantic 模型生成解析指令。
parser = PydanticOutputParser(pydantic_object=AnnotateMeta)

# --- 4. 创建提示模板 (Prompt Template) ---
# 这个模板包含了用户的原始输入（{text}）和解析器的格式化指令（{format_instructions}）。
# langchian 会自动将 PydanticOutputParser 生成的指令填充到 {format_instructions} 中。
prompt_template = """
请仔细阅读以下文本，并根据内容提取所需信息。

{format_instructions}

原始文本如下：
---
{text}
"""

prompt = ChatPromptTemplate.from_template(
    template=prompt_template,
    partial_variables={"format_instructions": parser.get_format_instructions()},
)

# --- 5. 创建并运行处理链 ---
# 我们使用 LCEL (LangChain Expression Language) 将提示、模型和解析器链接在一起。
# 这形成了一个清晰、可读的数据处理流程。
chain = prompt | llm | parser


async def do_with_text(input_text):
    # 运行链并获取结果
    result: AnnotateMeta = await chain.ainvoke({"text": input_text})
    print(result.model_dump_json(indent=2))

    return result


def convert_rows_to_csv(rows: List[AnnotateMeta]) -> str:
    """将 AnnotateMeta 对象列表转换为 CSV 格式的字符串"""
    csv_rows = [
        ",".join(
            [
                row.scenario,
                row.short_name or row.title,  # 使用分号分隔多个类型
                *[
                    "x" if t in row.type else ""
                    for t in [
                        "竞争型漏洞",
                        "多条路径检查不一致",
                        "代码设计与实现存在差异",
                        "越权型漏洞",
                        "权限检查缺失(完全没有检查)",
                        "权限检查不当",
                    ]
                ],
                *[
                    "x" if m in row.method else ""
                    for m in ["静态分析", "动态分析", "LLM"]
                ],
                *[
                    "x" if s in row.static_techs else ""
                    for s in ["控制流", "数据流", "符号执行"]
                ],
                *[
                    "x" if d in row.dynamic_techs else ""
                    for d in ["模糊测试", "动态污点分析"]
                ],
                *[
                    "x" if l in row.llm_techs else ""
                    for l in ["纯 LLM", "LLM + 程序分析"]
                ],
            ]
        )
        for row in rows
    ]
    return "\n".join(csv_rows)


async def main():
    jobs = []
    for txt in get_input_texts():
        jobs.append(do_with_text(txt))

    table = await asyncio.gather(*jobs)

    csv_output = convert_rows_to_csv(table)
    with open(os.path.join(__file__, "../output.csv"), "w", encoding="utf-8") as f:
        f.write(csv_output)


if __name__ == "__main__":
    asyncio.run(main())
