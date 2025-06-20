"""
Use this script to automate text annotation tasks
"""

import asyncio
import os
from pathlib import Path
from typing import Generator, List, Literal, Optional

from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

DEFAULT_MODEL = "gpt-4.1-mini"

CONTENT_ROOT = Path(__file__).parent / "data" / "sok-contents"


def get_input_texts() -> Generator[str, None, None]:
    """
    实际获取数据的入口，返回一个生成器，逐条返回数据。
    """

    for file in CONTENT_ROOT.glob("*.tex"):
        txt = file.read_text(encoding="utf-8")
        lines = txt.split("\n")
        for line in lines:
            l = line.strip()
            if not l or l.startswith("%") or len(l) < 10:
                continue

            yield l


# --- 1. 定义期望的输出结构 ---
class AnnotateMeta(BaseModel):
    """从所给的文本识别论文所述方法包括属于静态分析/动态分析下的哪一种方法"""

    # 使用 Field 来提供更详细的描述，引导 LLM更好地填充内容
    is_pure_latex_cmd: bool = Field(
        default=False, description="如果这一行是纯 LaTeX 命令，设为 True 无需总结方法"
    )
    static_methods: Optional[List[str]] = Field(
        default=None,
        description="所用到的静态分析方法列表，如污点分析",
    )
    dynamic_methods: Optional[List[str]] = Field(
        default=None,
        description="所用到的动态分析方法列表，如模糊测试",
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

chain = prompt | llm | parser


async def do_with_text(input_text):
    # 运行链并获取结果
    result: AnnotateMeta = await chain.ainvoke({"text": input_text})

    print(result.model_dump_json(indent=2))

    return result


async def main():
    static_methods = set()
    dynamic_methods = set()

    results = await asyncio.gather(*map(do_with_text, get_input_texts()))

    for result in results:
        if result.static_methods:
            static_methods.update(result.static_methods)
        if result.dynamic_methods:
            dynamic_methods.update(result.dynamic_methods)

    print("静态分析方法：", sorted(static_methods))
    print("动态分析方法：", sorted(dynamic_methods))


if __name__ == "__main__":
    asyncio.run(main())
