__author__ = 'dk'

import csv
import fnmatch
import os

from flowcontainer.extractor import extract

# 指定目录路径
directory = r'./pcap/'
headerHasWriteInFile = False
# 枚举所有以 .pcap 结尾的文件
doc_files = [f for f in os.listdir(directory) if fnmatch.fnmatch(f, '*.pcap')]
for doc_file in doc_files:
    print(doc_file)
    result = extract(directory + doc_file, filter='(tcp or udp)', extension=['tls.handshake.certificate'])
    for key in result:
        ### The return vlaue result is a dict, the key is a tuple (filename,procotol,stream_id)
        ### and the value is an Flow object, user can access Flow object as flowcontainer.flows.Flow's attributes refer.
        value = result[key]
        # 打开 CSV 文件并追加数据
        header = [
            'filename', 'protocol', 'serialNum', 'access ip src', 'access ip dst', 'access src port',
            'access dst port', 'access payload packet lengths', 'access payload packet timestamps sequence',
            'access ip packet lengths, (including packets with zero payload, and ip header)',
            'access ip packet timestamp sequence, (including packets with zero payload)',
            'access default lengths sequence, the default length sequences is the payload lengths sequences',
            'access sni of the flow if any else empty str'
        ]
        # key[0]
        with open('key[0]' + '.csv', mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            # 要追加的数据
            if not headerHasWriteInFile:
                writer.writerow(header)
                headerHasWriteInFile = True
            new_rows = [
                [key[0], key[1], key[2], value.src, value.dst, value.sport, value.dport, value.payload_lengths,
                 value.payload_timestamps, value.ip_lengths, value.ip_timestamps],
            ]
            # 写入数据行（注意：这里不需要写表头）
            writer.writerows(new_rows)
    print(len(result))
