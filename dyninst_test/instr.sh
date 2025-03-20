mutator_path=./DyninstBasicAdd    # 设置mutator工具路径
bin_path=./test                 # 二进制文件路径
mutatee_out_path=./test_instru    # 插桩后的输出路径

# 使用mutatee_out_path而不是未定义的filtered_path
$mutator_path $bin_path $mutatee_out_path
