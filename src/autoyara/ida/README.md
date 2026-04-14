# ida模块 使用说明

## 简介
`server.py` 是用于与IDA进行交互的服务端脚本，适用于在agent中集成MCP工具。

## 使用方法
1. 在agent中新建一个MCP工具，指定命令格式如下：

	 ```
	 PYTHON_PATH IDA_PATH
	 ```
	 - `PYTHON_PATH`：ida的Python解释器路径，在/configs/config中。
	 - `IDA_PATH`：IDA Pro的可执行文件路径，在/configs/config中。


2. 运行agent并开启MCP，ai可以调用./mcptools中记录的工具

### 工具说明
- `get_hex_from_ida`：
	- 功能：从IDA中提取指定函数的十六进制数据。
	
	- 用法：传入目标文件路径和函数名，工具会自动完成分析。
	
	- 结果：分析完成后，会在/logs目录下生成日志文件，在/tmp目录下创建对应的文件夹，/tmp/{uniq}/output.json中的hex字段即为提取的十六进制数据。同时会在/data/process目录下会生成分析后的数据库文件作为缓存

- `get_function_name_by_hex`：
    - 功能：根据指定的十六进制字符串（不带空格、全大写）在二进制中查找包含该字节序列的所有函数名。
    - 用法：传入目标文件路径和 hex_str（如 `A1F30F1EFA554889E5B8...`），返回所有包含该字节序列的函数名列表。


