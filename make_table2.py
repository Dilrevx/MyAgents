import re
from os import path

import pandas as pd
from langchain.chat_models import init_chat_model
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

INPUT_XLSX = path.join(path.dirname(__file__), "input.xlsx")
OUTPUT_CSV = path.join(path.dirname(__file__), "output.csv")


TEX_COLUMN_NAMES = r"    工作名称 & 目标程序 & 分析模式 & 分析方法 & LLM 用途  & LLM 实现方法".strip().split(
    " & "
)


def load_input_table_df():
    df = pd.read_excel(INPUT_XLSX, sheet_name="Sheet3")

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
    # df["应用场景"] = df["应用场景"].ffill()
    # df.drop(index=0, inplace=True)  # Remove the first row which is a header row
    return df


MISSPELLING_MAP = {
    "finetuning": "微调",
    "fintuning": "微调",
    "finetuing": "微调",
    "prompt engineering": "提示工程",
    "prompt Engineering": "提示工程",
    "finetuing、prompt engineering": "微调+提示工程",
    "静态": "静态分析",
    "动态": "动态分析",
}


def main():
    csv_df = load_input_table_df()

    out_tex_rows = []
    for i, csv_row in csv_df.iterrows():
        new_row = {
            "工作名称": csv_row["工作名称"],
            "目标程序": csv_row["目标程序"],
            "分析模式": csv_row["分析模式"],
            "分析方法": csv_row["分析方法"],
            "LLM 用途": csv_row["LLM 用途"],
            "LLM 实现方法": csv_row["LLM 实现方法"],
        }

        for k, v in new_row.items():
            if v in MISSPELLING_MAP:
                new_row[k] = MISSPELLING_MAP[v]

        out_tex_rows.append(new_row)

    out_tex_rows = list(
        map(lambda row: [row[col.strip()] for col in TEX_COLUMN_NAMES], out_tex_rows)
    )
    out_tex_lines = map(
        lambda row: " & ".join(row) + r" \\",
        out_tex_rows,
    )
    out_tex_content = "\n".join(out_tex_lines)
    print(out_tex_content)


if __name__ == "__main__":
    main()
