医院 IES 八工况及关联试验原始数据（2026-11-10）

数据入口
https://github.com/HanqinXie/ies_hospital_data/releases/tag/raw-data-20261110

本仓库存放目录、SHA-256 清单、版本说明和下载恢复工具。原始数据以同仓库 Release 的独立 ZIP 分卷分发，每卷不超过 400,000,000 字节。跨卷的大文件由清单记录片段及其位置；恢复工具可按原始字节重建，未平滑、插值、重算或改写科学记录。
发布前必须完成分卷及所有原始文件的流式完整性校验；发布后的附件信息以 Release 和 catalog/ASSETS.json 为准。

本次交付共 2,236 个原始文件、66,184,331,558 字节，封装为 245 个分卷、14,305,125,695 字节。最大卷 336,928,877 字节。所有原文件、2,325 个片段和全部分卷已通过本地全量 SHA-256 校验。完整 RAW_MANIFEST.json 的 SHA-256 为：
62c793ab45e42b5c8e3143cdbf73d2cd6439c313f48523a9ffc43c1c2273d725

数据范围
A 最终八工况：2026-11-05 源分区修复 campaign03 的 8 条新 U，加上对应的 8 条既有 R 与 5 条唯一正常 N，共 21 组来源、24 个逻辑工况与对照引用。
B 故障前准备：公共预热、初态、COMMON_CHECKPOINT、冻结分配和命令队列；这些是各次事故的组成部分，不增加独立样本数。
C 单设备机制：单塔和单泵各 U/U0/R，共 6 条完整轨迹，保留其较早生成版本。
D 参数与背景：96 次实际尝试，包括 90 次完成、6 次失败或停止；原始 ZIP、各次工况、状态和归档索引均保留。完成输出为原批 86 条、r1 修复 3 条、r3 修复 1 条，不能合称同源数据。
  同时提供其引用的 12 条历史基线原件：其中 2 条与 C 的 TOWER_U/R 共用，另 10 条原来源另行补齐；12 条的 SEGMENTS 与 RESULT 共 24 项 SHA 均与原历史引用精确匹配。不能用最终 campaign03 或 replot 的新轨迹代替这些历史原件。
E 恢复策略：T05_R1、T06_R1、T05_R2 三条完整轨迹，以及 T05_R1 的失败前缀。T06_R1 原外层进程退出码为 1、native 完成，必须结合原 WRAPPER_COMPLETION 收据读取，不能抹去该区别。
F 修复前后：fixed_branch_replot_run03 的 8 组 common/U/R 原件。其 8 条 R 已被 A 复用，文件存储与清单避免重复源文件，不能重复计数。
G 步长与模型一致性：38 次实际尝试（36 个 completed、2 个 failed），另保留一次非实际 failed_spawn 元数据。最新 C7 只有 6 条完整 T06 验证轨迹；完整 24 条资格试验、选步和生产均未完成。
H 停止与失败：源分区早期 campaign/campaign02 的停止前缀，以及上述各批原始异常、求解记录和停止收据。这些记录不构成完成的事故尾段，不能将缺失尾段填零。

原始文件
SEGMENTS.jsonl：实际分段时刻、需求、供能、设备实际出力、缺供、库存、燃料与费用。
STATES.jsonl：设备、储能、命令队列、执行状态和热状态。
DECISIONS.jsonl：当时可见观测、请求动作与诊断。
EVENTS.jsonl：故障、动作与状态变化的实际时刻和参数。
SOLVER_LOG.jsonl：原留存求解记录。U 无优化分支的日志可以为空，公共准备阶段的求解日志另在 common 中，不能把空日志当成缺档。
CASE、INITIAL_STATE、RESOLVED_CASE、RESULT、FAILURE、SOURCE_BINDING 等文件保留工况、初态、结果、异常与版本来源。

版本与完整性说明
1. 最终八工况 T05 为单塔故障，T06 为单主泵支路故障；T08 有自己的最终 U/R 路径。不能继续使用早期 family19 中的 T05/T08 producer 复用计数来描述最终包。
2. D 类参数试验虽有后续运行日期，其 noopt 实现仍早于最终源分区修复。G 类候选验证也不等于最终模型通过。
3. G 实际索引 31 的历史 master 注册文件路径后来被改写；保留实际 LAUNCH、CASE、绑定和原始前缀，并在 scope_g_summary.json 披露登记 SHA 与当前文件 SHA 不同，不能冒称历史字节相同。
4. G 实际索引 33 在启动阶段失败，从未生成 SEGMENTS，缺口如实保留。
5. 各类存在复用，不能把分组数量相加作为独立事故样本数。完整输出状态、专项核账、全模型科学资格各有自己的范围。
6. 未包含 EnergyPlus 原文件、8760 全年数据、年度运行、图片、Markdown、许可文件或凭据。本次仅整理与传输现有文件，没有启动仿真、训练、优化，也没有恢复暂停的实验。

下载、校验与恢复（Python 标准库）
git clone https://github.com/HanqinXie/ies_hospital_data.git
cd ies_hospital_data
python tools/download_raw.py --destination <分卷保存目录>
python tools/restore_raw.py --manifest catalog/RAW_MANIFEST.json --assets <分卷保存目录> --verify-only
python tools/restore_raw.py --manifest catalog/RAW_MANIFEST.json --assets <分卷保存目录> --destination <新的恢复目录>

下载器会校验分卷 SHA-256；恢复工具会校验原文件字节及 SHA-256。请预留完整原始数据所需空间，已有不同内容的文件不会被自动覆盖。只验证而不另建全量副本时使用 --verify-only。

catalog/DATA_GROUPS.json 给出各类原始数据目录及用途；catalog/FINAL_EIGHT_CASES.json 是最终八工况的准确来源映射；catalog/RAW_MANIFEST.json 和 catalog/ASSETS.json 给出本次交付实际内容。
