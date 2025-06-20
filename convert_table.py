import re
from pathlib import Path
from typing import Dict, List

ROOT_DIR = Path(__file__).parent

INPUT_TEX = ROOT_DIR / "input.tex"
OUTPUT_TEX = ROOT_DIR / "output.tex"


def load_table_from_tex(path: Path):
    columns = "_ & ref & 竞争型漏洞  & 越权漏洞 & 协议实现不当 & \
        校验不一致 & 权限检查缺失 & 权限检查不当 & placeholder1 \
         & 静态分析 & 动态分析 & 大模型分析 ".split(
        "&"
    )
    columns = [col.strip() for col in columns]

    txt = path.read_text(encoding="utf-8")
    lines = txt.split("\n")

    rows = []
    for line in lines:
        line = line.strip()
        if line.startswith("&") and line.endswith("\\\\"):
            cells = line.split("&")
            cells = [cell.strip() for cell in cells]
            assert len(cells) == len(columns), f"Row length mismatch: {cells}"
            row = dict(zip(columns, cells))
            rows.append(row)
    return columns, rows


"""

应用场景    论文名称(工具名或作者名) 竞争型漏洞 越权行为 不一致性 权限检查缺失 权限检查不当 代码设计与现实差异   静态   动态  LLM

"""


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


def swap_columns(rows: Dict[str, str], columns: List[str]):
    """
    Swap two columns in the table.
    """
    index1 = columns.index("越权漏洞")
    index2 = columns.index("校验不一致")

    columns[index1], columns[index2] = columns[index2], columns[index1]
    columns = (
        columns[:5] + ["placeholder1"] + columns[5:11] + ["placeholder1"] + columns[11:]
    )

    ret = []
    for row in rows:
        s = " & ".join(row[col] for col in columns)
        ret.append(s)
    return ret


def main():
    columns, rows = load_table_from_tex(INPUT_TEX)
    print("Columns:", columns)
    print("Rows:", rows)

    # NOTE: currently desired feature: swap columns
    OUTPUT_TEX.write_text("\n".join(swap_columns(rows, columns)), encoding="utf-8")


if __name__ == "__main__":
    main()
