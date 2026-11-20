# 第三方组件

mocat 节点发行包中附带以下以**独立进程**方式调用的程序（未链接进 mocat，见需求文档 NF-09 / 附录 A.4）：

| 程序 | 版本 | 许可证 | 源码 |
| --- | --- | --- | --- |
| fakehttp | 0.9.18 | GPL-3.0 | <https://github.com/MikeWang000000/FakeHTTP/archive/refs/tags/0.9.18.tar.gz> |
| fakesip | 0.9.1 | GPL-3.0 | <https://github.com/MikeWang000000/FakeSIP/archive/refs/tags/0.9.1.tar.gz> |

二者静态链接了以下库（同样从固定版本源码编译）：

| 库 | 版本 | 许可证 | 源码 |
| --- | --- | --- | --- |
| libmnl | 1.0.5 | LGPL-2.1+ | <https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2> |
| libnfnetlink | 1.0.2 | GPL-2.0+ | <https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2> |
| libnetfilter_queue | 1.0.5 | GPL-2.0+ | <https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2> |

构建方法见 `scripts/build-fake.sh`（未修改上游代码）。GPL-3.0 许可证全文随包附带（`LICENSE.fakehttp`、`LICENSE.fakesip`）。
