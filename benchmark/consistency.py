import re
import os

def extract_block_info(log_file):
    """
    提取日志中所有形如 'commit Block round X node Y batch_id Z' 的三元组 (round, node, batch_id)
    """
    pattern = re.compile(r'commit batch (\d+)')
    block_info = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            matches = pattern.findall(line)
            block_info.extend(matches)
    return block_info

def compare_block_sequences(log_files):
    """
    比较多个 log 文件中 Block 提交序列是否一致，并输出不一致的三元组。
    """
    block_sequences = {}
    for log_file in log_files:
        blocks = extract_block_info(log_file)
        block_sequences[log_file] = blocks

    # 获取第一个文件作为参考
    ref_file, ref_blocks = next(iter(block_sequences.items()))
    consistent = True

    for file, blocks in block_sequences.items():
        if file == ref_file:
            continue

        min_len = min(len(ref_blocks), len(blocks))
        for i in range(min_len):
            if blocks[i] != ref_blocks[i]:
                print(f"差异位置 {i}:")
                print(f"  {ref_file}: {ref_blocks[i]}")
                print(f"  {file}: {blocks[i]}")
                consistent = False

        # 检查是否有额外的项
        if len(ref_blocks) != len(blocks):
            print(f"{file} 与 {ref_file} 序列长度不一致：{len(blocks)} vs {len(ref_blocks)}")
            extra = blocks[min_len:] if len(blocks) > min_len else ref_blocks[min_len:]
            print(f"  额外项: {extra}")
            consistent = False

    if consistent:
        print("所有文件的 Block 提交序列完全一致。")
    return consistent

if __name__ == '__main__':
    log_dir = 'logs/2025-07-14-16-59-39'
    log_files = [
        os.path.join(log_dir, 'node-info-0.log'),
        os.path.join(log_dir, 'node-info-1.log'),
        os.path.join(log_dir, 'node-info-2.log'),
        os.path.join(log_dir, 'node-info-3.log'),
    ]
    compare_block_sequences(log_files)
