import re
from os import path

import pandas as pd
from langchain.chat_models import init_chat_model
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

INPUT_XLSX = path.join(path.dirname(__file__), "input.xlsx")
OUTPUT_CSV = path.join(path.dirname(__file__), "output.csv")

TEX_SRC_DATA = r"""

% &  & 竞争 & \makecell{校验\\不一致} & \makecell{协议\\实现不当} &  & 越权 & 检查缺失 & 检查不当 &  & 控制流 & 数据流 & 符号执行 & & 模糊测试& 插桩 & & 仅 LLM & \makecell{LLM+\\程序分析}  \\
                \midrule   

\multirow{19}{*}{移动端}
 & Kratos~\cite{shao2016kratos} &  & \ding{72} &  &  & \ding{72} &  & \ding{72} &  & \checkmark &  &  & \\
 & DroidDiff~\cite{10.5555/3241094.3241183} &  & \ding{72} &  &  & \ding{72} &  & \ding{72} &  & \checkmark &  &  & \\
 & AuthScope~\cite{10.1145/3133956.3134089} &  &  &  &  & \ding{72} &  & \ding{72} &  &  & \checkmark &  & \\
 & AceDroid~\cite{aafer2018acedroid} &  & \ding{72} &  &  & \ding{72} &  & \ding{72} &  & \checkmark &  &  & \\
 & FIRMSCOPE~\cite{251554} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & ReM$^3$~\cite{10.1145/3460120.3485374} &  &  &  &  & \ding{72} &  & \ding{72} &  & \checkmark &  &  & \\
 & RECAST~\cite{10.1145/3548606.3560666} & \ding{72} &  &  &  &  &  &  &  &  & \checkmark &  & \\
 & PredRacer~\cite{10589749} & \ding{72} &  &  &  &  &  &  &  &  & \checkmark &  & \\
 & Zhang L et.al~\cite{280044} & \ding{72} &  &  &  &  &  & \ding{72} &  & \checkmark & \checkmark &  & \\
 & IAceFinder~\cite{zhou2022uncovering} &  & \ding{72} &  &  &  &  & \ding{72} &  & \checkmark &  &  & \\
 & CMRFScanner~\cite{10.1145/3548606.3560597} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & Zhao Y et.al~\cite{10.1145/3605762.3624433} &  &  &  &  &  & \ding{72} &  &  & \checkmark &  &  & \\
 & TDCAttack~\cite{10.1145/3605762.3624430} &  &  &  &  & \ding{72} &  & \ding{72} &  & \checkmark & \checkmark &  & \\
 & MiniCAT~\cite{10.1145/3658644.3670294} &  &  &  &  & \ding{72} &  & \ding{72} &  & \checkmark &  &  & \\
 & Zhang Z et.al~\cite{10506090} &  &  &  &  &  &  & \ding{72} &  & \checkmark & \checkmark &  & \\
 & MiniChecker~\cite{10.1145/3691620.3695534} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \\
 & Georgiev et.al~\cite{georgiev2014breaking} &  &  &  &  & \ding{72} &  & \ding{72} &  & \checkmark & \checkmark &  & \\
 & BigMAC~\cite{247662} &  & \ding{72} &  &  & \ding{72} &  &  &  & \checkmark &  &  & \\
 & Apinat~\cite{10.1145/3372297.3417255} &  &  &  &  &  &  & \ding{72} &  &  & \checkmark &  & \\
 
\midrule

\multirow{15}{*}{操作系统}

& DDRace~\cite{10.5555/3620237.3620397} & \ding{72} &  &  &  &  &  &  &  & \checkmark & \checkmark &  & \\
 & HistLock+~\cite{8375648} & \ding{72} &  &  &  &  &  &  &  &  & \checkmark &  & \\
 & Razzer~\cite{8835326} & \ding{72} &  &  &  &  &  &  &  & \checkmark & \checkmark &  & \\
 & SDRacer~\cite{8835326} & \ding{72} &  &  &  &  &  &  &  & \checkmark & \checkmark &  & \\
 & AutoISES~\cite{10.5555/1496711.1496737} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & IPPO~\cite{10.1145/3460120.3485373} &  & \ding{72} &  &  &  &  &  &  & \checkmark &  &  & \\
 & ESSS~\cite{298112} &  & \ding{72} &  &  &  & \ding{72} &  &  & \checkmark &  &  & \\
 & Kobold~\cite{9152695} &  &  &  &  &  & \ding{72} & \ding{72} &  & \checkmark & \checkmark &  & \\
 & PeX~\cite{236362} &  &  &  &  &  & \ding{72} &  &  & \checkmark &  &  & \\
 & MPCHECKER~\cite{10.1145/3548606.3560589} &  &  &  &  &  & \ding{72} &  &  & \checkmark & \checkmark &  & \\
 & iService~\cite{10.1145/3564625.3568001} &  &  &  &  &  & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & LRSan~\cite{10.1145/3243734.3243844} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \\
 & GOSONAR~\cite{GoSonar} &  &  &  &  &  & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & CLFuzz~\cite{zhou2023clfuzz} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \\
 & AGLFuzz~\cite{zhao2025aglfuzz} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \\
 
\midrule
 
 \multirow{13}{*}{Web}

& Lu K et.al~\cite{236280} &  & \ding{72} &  &  &  &  &  &  & \checkmark &  &  & \\
 & Sun et.al~\cite{10.5555/2028067.2028078} &  &  &  &  & \ding{72} & \ding{72} &  &  & \checkmark &  &  & \\
 & MACE~\cite{10.1145/2660267.2660337} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & ACIDRain~\cite{10.1145/3035918.3064037} & \ding{72} & \ding{72} &  &  &  &  &  &  &  & \checkmark &  & \\
 & BolaRay~\cite{10.1145/3658644.3690227} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & MOCGuard~\cite{MOCGuard} &  &  &  &  & \ding{72} & \ding{72} & \ding{72} &  & \checkmark &  &  & \\
 & ReqRacer~\cite{10.1145/3468264.3468594} & \ding{72} &  &  &  &  &  &  &  &  & \checkmark &  & \\
 & IRIS~\cite{li2025iris} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & Artemis~\cite{li2025iris} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & LI P et.al~\cite{li2025automated} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & LLMSA~\cite{li2025automated} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & Taintmini~\cite{10172538} &  &  &  &  &  &  &  &  & \checkmark &  &  & \\
 & MiniTracker~\cite{10197457} &  &  &  &  & \ding{72} &  &  &  & \checkmark &  &  & \\
 
\midrule


\multirow{18}{*}{Web3}

 & SmartInv~\cite{wang2024smartinv} &  &  &  &  &  &  & \ding{72} &  & \checkmark & \checkmark &  & \checkmark \\
 & HighGuard~\cite{10.1145/3691620.3695356} &  &  & \ding{72} &  &  &  & \ding{72} &  &  & \checkmark &  & \\
 & FuzzDelSol~\cite{10.1145/3576915.3623178} &  &  &  &  & \ding{72} &  & \ding{72} &  &  & \checkmark &  & \\
 & ItyFuzz~\cite{10.1145/3597926.3598059} &  &  & \ding{72} &  &  &  & \ding{72} &  &  & \checkmark &  & \\
 & STING~\cite{10.5555/3620237.3620336} &  &  &  &  &  &  & \ding{72} &  &  & \checkmark &  & \\
 & CAI J et.al~\cite{10926491} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \\
 & DeFiRanger~\cite{wu2023defiranger} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & LOKI~\cite{ma2023loki} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & fAmulet~\cite{li2024famulet} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & ZKAP~\cite{wen2024practical} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & Evmfuzz~\cite{fu2024evmfuzz} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & Fluffy~\cite{yang2021finding} &  &  & \ding{72} &  &  &  &  &  &  & \checkmark &  & \checkmark \\
 & CHEN C et.al~\cite{chen2025chatgpt} &  &  &  &  &  &  & \ding{72} &  &  &  &  & \checkmark \\
 & GPTScan~\cite{sun2024gptscan} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & PropertyGPT~\cite{liu2024propertygpt} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 & Smart-LLaMA~\cite{yu2024smart} &  &  &  &  &  &  & \ding{72} &  &  &  &  & \checkmark \\
 & MA W et.al~\cite{ma2024combining} &  &  &  &  &  &  & \ding{72} &  &  &  &  & \checkmark \\
 & AdvSCanner~\cite{wu2024advscanner} &  &  &  &  &  &  & \ding{72} &  & \checkmark &  &  & \checkmark \\
 
 \bottomrule
  \end{tabular}
  }
\end{table*}
"""

TEX_COLUMN_NAMES = [
    "应用场景",
    "论文名称(工具名或作者名)",
    "竞争型漏洞",
    "不一致性",
    "代码设计与现实差异",
    "_1",
    "越权行为",
    "权限检查缺失",
    "权限检查不当",
    "_2",
    "静态分析",
    "动态分析",
    "_3",
    "大模型分析",
]

TEX_NEW_COLUMN_NAMES = [
    "应用场景",
    "论文名称(工具名或作者名)",
    "竞争型漏洞",
    "不一致性",
    "代码设计与现实差异",
    "_1",
    "越权行为",
    "权限检查缺失",
    "权限检查不当",
    "_2",
    "控制流",
    "数据流",
    "符号执行",
    "_3",
    "模糊测试",
    "插桩",
    "_4",
    "仅LLM",
    "LLM+程序分析",
]


def parse_tex_table(col_names, tex_data):
    """
    Parse the LaTeX table from the given tex_data and return a DataFrame.
    """
    # Extract rows from the LaTeX table
    rows = []
    for line in tex_data.split("\n"):
        line = line.strip().replace("\\\\", "")
        if line.startswith("&"):
            # Split the line by "&" and strip whitespace
            row = [cell.strip() for cell in line.split("&")]
            rows.append(row)

    # Create a DataFrame
    df = pd.DataFrame(rows, columns=col_names)
    return df


def load_input_table_df():
    df = pd.read_excel(INPUT_XLSX, sheet_name="Sheet2")

    # Fix headers
    # df.rename(
    #     columns={
    #         "漏洞类型": "竞争型漏洞",
    #         "Unnamed: 3": "越权行为",
    #         "Unnamed: 4": "不一致性",
    #         "Unnamed: 5": "权限检查缺失",
    #         "Unnamed: 6": "权限检查不当",
    #         "Unnamed: 7": "代码设计与现实差异",
    #         "方法": "静态",
    #         "Unnamed: 9": "动态",
    #         "Unnamed: 10": "LLM",
    #     },
    #     inplace=True,
    # )
    df["应用场景"] = df["应用场景"].ffill()
    # df.drop(index=0, inplace=True)  # Remove the first row which is a header row
    return df


"""

应用场景    论文名称(工具名或作者名) 竞争型漏洞 越权行为 不一致性 权限检查缺失 权限检查不当 代码设计与现实差异   静态   动态  LLM

"""


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
    csv_df = load_input_table_df()
    tex_ref_df = parse_tex_table(TEX_COLUMN_NAMES, TEX_SRC_DATA)

    out_tex_rows = []
    for i, ((_1, csv_row), (_2, tex_row)) in enumerate(
        zip(csv_df.iterrows(), tex_ref_df.iterrows())
    ):
        assert i == _1 == _2
        assert all(
            [
                (csv_row[col] == "x" and tex_row[col] in [r"\ding{72}", r"\checkmark"])
                or (csv_row[col] != "x" and tex_row[col] == "")
                for col in [
                    "竞争型漏洞",
                    "越权行为",
                    "代码设计与现实差异",
                    "不一致性",
                    "权限检查缺失",
                    "权限检查不当",
                ]
            ]
        )
        new_row = {
            "应用场景": " ",
            "论文名称(工具名或作者名)": tex_row["论文名称(工具名或作者名)"],
            "竞争型漏洞": r"\ding{72}" if csv_row["竞争型漏洞"] == "x" else "",
            "不一致性": r"\ding{72}" if csv_row["不一致性"] == "x" else "",
            "代码设计与现实差异": (
                r"\ding{72}" if csv_row["代码设计与现实差异"] == "x" else ""
            ),
            "_1": "",
            "越权行为": r"\ding{72}" if csv_row["越权行为"] == "x" else "",
            "权限检查缺失": r"\ding{72}" if csv_row["权限检查缺失"] == "x" else "",
            "权限检查不当": r"\ding{72}" if csv_row["权限检查不当"] == "x" else "",
            "_2": "",
            "控制流": r"\checkmark" if csv_row["静态-控制流"] == "x" else "",
            "数据流": r"\checkmark" if csv_row["静态-数据流"] == "x" else "",
            "符号执行": r"\checkmark" if csv_row["静态-符号执行"] == "x" else "",
            "_3": "",
            "模糊测试": r"\checkmark" if csv_row["动态-模糊测试"] == "x" else "",
            "插桩": r"\checkmark" if csv_row["动态-插桩"] == "x" else "",
            "_4": "",
            "仅LLM": r"\checkmark" if csv_row["纯LLM"] == "x" else "",
            "LLM+程序分析": r"\checkmark" if csv_row["LLM结合传统方法"] == "x" else "",
        }
        out_tex_rows.append(new_row)

    assert len(out_tex_rows) == len(csv_df) == len(tex_ref_df) == 65

    out_tex_rows = list(
        map(lambda row: [row[col] for col in TEX_NEW_COLUMN_NAMES], out_tex_rows)
    )
    out_tex_lines = map(
        lambda row: " & ".join(row) + r" \\",
        out_tex_rows,
    )
    out_tex_content = "\n".join(out_tex_lines)
    print(out_tex_content)


if __name__ == "__main__":
    main()
