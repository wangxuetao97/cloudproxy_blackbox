# 配置说明
ap_hostname         初始化阶段获取cp的ap节点列表，以及之后测试使用的ap节点列表。
local_cloudproxy    使用127.0.0.1作为proxy地址，不从ap里获取地址。
use_dns_ap          忽略ap_hostnames从ap.agora.io里DNS获取ap地址，只获取一个ip。
ignore_ap_has_no_cp 忽略ap里找不到tcp_proxy/udp_proxy/tls_proxy地址的错误。
ignore_ap_fail      在测试目标ap连接不上的时候不向agolet汇报。
