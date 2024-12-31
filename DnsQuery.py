"""
使用dnspython库工作，返回结果仅供参考。
"""

import dns.resolver
import re

def is_valid_domain(domain):
    # 排除 IPv4 地址
    ipv4_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    if ipv4_pattern.match(domain):
        return False

    # 排除 IPv6 地址
    ipv6_pattern = re.compile(
        r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,7}:$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}$|"
        r"^[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}$|"
        r"^:(?::[A-Fa-f0-9]{1,4}){1,7}$"
    )
    if ipv6_pattern.match(domain):
        return False

    # 正则表达式验证域名格式
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*(?<!-)$"
    )
    # 检查域名长度
    if len(domain) > 253:
        return False
    # 检查域名格式
    return bool(domain_pattern.match(domain))

def clean_domain(domain):
    # 去除域名前的 "https://" 或 "http://"
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]
    # 去除域名后的 "/" 如果有的话
    domain = domain.rstrip('/')
    # 检查是否为有效域名
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain

def query_dns_record(domain, record_type, tcp=False):
    domain = clean_domain(domain)  # 清理域名
    try:
        back_value = []
        answers = dns.resolver.resolve(domain, record_type, tcp=tcp)
        print("Non-authoritative answers")
        for rdata in answers:
            if record_type == "A" or record_type == "AAAA":
                back_value.append(rdata.address)
            elif record_type == "CNAME":
                back_value.append(rdata.target)
            elif record_type == "NS" or  record_type == "MX":
                back_value.append(str(rdata))
        return back_value
    except dns.resolver.NoAnswer:
        print(f"Not Found {domain}'s {record_type} record")
        return None
    except dns.resolver.NXDOMAIN:
        print(f"Not Found domain {domain}")
        return None
    except Exception as e:
        print("Error!\n", e)
        return None

# 也可以直接调用 query_dns_record 查询
