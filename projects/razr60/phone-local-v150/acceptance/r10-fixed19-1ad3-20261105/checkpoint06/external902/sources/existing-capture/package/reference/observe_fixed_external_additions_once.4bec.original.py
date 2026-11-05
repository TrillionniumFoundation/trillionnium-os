#!/usr/bin/env python3
"""Collect only the fixed later 72 added originals, six directory rows and two boundary leaves."""
import sys
sys.dont_write_bytecode=True
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import zlib

ANDROID=Path('/proc/1/root')
BOOT='f8019f83-20a7-4f18-bea1-51c980621e4d'
BASE=Path('/var/lib/trillionnium/owner-open/phone-local-v150')
EXTERNAL_LABEL='root-r10-neg01-7c907661-01'
EXTERNAL_NONCE='902e851c3ca1f90deab3d880ab993774'
CLIENT_NONCE='5a952602788122f47ff1370cfa38dffe'
RUN_BASENAME='20261105-114342-902e851c3ca1f90deab3d880ab993774'
RUN=BASE/'component-probe-r6/evidence'/RUN_BASENAME
CLIENT=BASE/'client-receipts'
BOUNDARY_PARENT=BASE/'native-guard-boundaries-r10-r1'
BOUNDARY_PATHS=(str(BOUNDARY_PARENT/(EXTERNAL_NONCE+'.json')),str(BOUNDARY_PARENT/EXTERNAL_NONCE))
OUTPUT_LIMIT=8*1024*1024
BOUNDARY_FILE_LIMIT=1024*1024
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
READSET={}
DIRECTORIES={}
READ_BYTES=0
PRIOR_SCAN_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_neg01_1ad3_02/reconciliation/inventory-diff-read01/originals/PHONE-STDOUT.original', 'bytes': 972811, 'sha256': '8b053a62fc618d86a4b781e8a5a02585bc5488ee68f06f002ade6954cbaa9d55'}
OBSERVED_INVENTORY_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_neg01_1ad3_02/reconciliation/inventory-diff-read01/OBSERVED-INVENTORY.original.json', 'bytes': 878193, 'sha256': '5e5c3cb61863a87d3c5f499eb79aedd62f2bb3c49f40fbffa9d3cc69cab268c6'}
EXTERNAL_ROOT_PLAN_REFERENCE={'path': '/workspace/scratch/1ad3d6f55439/actual_external_902e_7c907661_01/ROOT-PLAN.original.json', 'bytes': 4783, 'sha256': '9a94108ffc737133ba879bd9cccd70c7ec3ae2f3da17eb689e5b1d5610789d58'}
DESCRIPTOR_TABLE_PIN=(33685, 'e56e6b5bddb3637f9676ef76ac0c92a9021a88b2d5957e06aec3c2abba838255')
DESCRIPTOR_ZLIB_PIN=(5701, '9303d806b089e838928fe87d3cc99207a6093c9295cc196d88375e124d953d92')
DESCRIPTOR_ZLIB_BASE64='eNrtXW1vJMdx/p6fwc+3uu7q6pfyN8UwAgOOFdhBECAwiH7VMeaRDLl3tmD4v/vp5R05MzuzO6JE7sqI9EFiT/Vuz9PVVU/VVM3+7SKWUstlvdneX9WHi1/9z98ubtNDvf9cy8Wv/naRftj2UeP43cWfr24wdtGuruvFu4uPdRtL3EZMcVYF905b55V9Z4y29E7hX/2uT9NeTPCijBVnRFvbRffH/vTu4uFDJOvwDWLIFZNsKcWUbIrG/2pnmZxI0klIZfGsWIoIm6TJ2hp1InHBJDLx4u/vLu7i9gM+6v3neP/++iq9x+1dX1/d3txcffr4/vYvN/V+c3tXb97ffbi9qZvr2xyvN5+1Ve/z9RXA2NzXXK/utg/vbRRLTpEPQRM19q1p41Vu0YTSWv0mX8erj9/878PtDb53Fj3Gba6ATwvLCL7dvCesPHu9w8qOxuzj2BC/mGy0xNW1ooCItGrw0akYxQmy2UmuTMb6VJiNac3WVLlRYraAOb0tfvf14dP1dh7AL5iVK3zc9vb+h3ng/A4TbP4jcPTOMDAcgOT8PnBfxwDcTfy4U/0LpTa73bwsn+5juq6Xqbbb+3q5vY83D3e3919W+e5C6c3Dbf5z3V7m+xq39TJut/Xj3fN1Gl8vTxfMJgNE3M3eFP56ZSBtN3e13l9eFUB6tf3h8v8+1fsfnq66x6uf6/1VuxrM8kAfkg/by4d6U3AT31/dPF0Mw4vP3y4Yxi3ePNTLDzUWfOxomlZ713c7/Pn5a7V+Fkm35YfJB9Dz1b2Z5vna53h9VYaIad48wX+Zbz/eXddtfbz4pzfV06dVbO7d0km3xq+xk1bU6KD3aQOb+OWcu7mx0TmHkUystSfvq86iJWqWUFSpSdtQtM4liGObg2skQcg2RaRMFVOtqhcnw+/9ypO2ALPW5FbhjP8Mcd7NewHQLhWJPorLKrboqk1RSQ4qZhujc5F1Uk4pXbEfhYGEBBdTDMYJq+T5lEAftFSL+Gpaga+x2k/w1TTC0s7ga/fxDZlLDVwVpQoS4UtSCq4+OG1SoKx9EfgyHQi6jn+SJVEOH+OUDpIynRLfeUu/DOw6IiUyBZZfAiyl7ChAD43BbTRXKErQBppcQJvYlKiqMzh7Tafim67BaB9JWlLWZzKnBHbBUy4iq/QKZC0DyDGymPcCZJtxqWqnOShH4FOKujR7RVI8F0WaSw5sVG2OFJXAUlWo3vhscbWdEtk9prFsZtdg6oNTUzM7xlRmMJV9TFlDX0FBqUacfI5Vleidr4bIg86yVqnU6qJjhA1KZaiucpya0VVH2IJTYnqAqS2hSyttgZsYWZrYgpXoemfYZKt8iImYgpHK2YtPkqpKquQYUjRKGyisxufAdYlKTrmMCIK1PyW6s0x3EVcyK3BlHNYJrpj3Alzh/TUwapKVhrImUT65KL4EVRFchYQwlZJNNtuWJGa4NjbeJliH6orPp8R1OVJYVtpV4HpxU6UdgRtmUgFhJhVgIjAsArMacrCZFLhzgker4mPPDxCAVDU3h2swROC7LTTHjG2QAp52SnDnIq1FWM0aS+uMsxNYjX4JrPD6KefscQgySWq4hZaLbsQMjpByFACbG9BuHLLratucVPylSzNBnRLWg5HqMr5hDb5iZYpvGCYNrN1PJNiZDExjDp4c7G0oQbN3CL50RHxQPbiCiMeNhejBwVxqJQDcArusHRwaPjOf0tYejfSXze4aiMHZzdTsjiGWGYhlH2IoqqbmVI0gqlHnbFoyFtGWiUmAq1MBIbG1ChLOlGAhDJpmg2RblYunhPhApmQJXaPXRLzW0ITe9nnDrJeZyYSZfXRBWEHADDtPsMCpqNKjrUSJLGXEuiVG6CxncSFTNga+D7oC1wZ2AUpxSgOxnGlaxnaN5sKF0RTb8COyjE/YZkM5gUtQVZGjwLxCb6GpCHU9gAaj1ck1DfemoKpULTvKQhLBFnwOpwzKDmTqFsGFSV1BGJin4GLeC8D1ycIwwJll4OusL9xAc0FqPb5JU7RG4U9EFibCSDc4NFO0N8FkxirUKVM1BzKdL8uLI04Kg7w4T/Pidsad2YE7e8qLx5zr3SAnG/P2E+75L/j6jVLfXN1sB6nkycWHpUv60Dw9mpfj3fYThq9r+R7g70QSILi6+X4qcnt/BVsarx+ex74pVw/Y0vxhM/7Cr5dv4hY2AjHxx4/xpnzz8GFw7evHzV/FWcCWYPrtU5677xu0AlqAGBvbmbdPn/FV5PrqAcvAfbR4dd0/5sv4o2Z94YzPs7Z/3eLi3f3tZwSX97iHjmqfcj0d1nPD+2O3n7azH4Hxp8H729vt5qFuP92NEH2oAGF7lTfKq0ZGWXAbhOmhuBRSEei1J1tTLjZaFzmVkBgsyEmDEjrVTNZB6ZzU13vexoc/b+Ld3eYh40g9jdb7j8+I/bQ0/9N+4D5T7ees9tu9yfU9KXJaI3TXmg3TRhTVYHU2OeomqtSYQByCAqEQ43dp3Pmsv13hmxnB45i892lfDx55kkeSI3NjQwuHgAgRuWUE6Q22JEgJJe7MSSsK3DJYVbWvBZTIB+UR5VOwrYEIkZaQ5eJc4Hw/NisL4Bq7ilfC1I155W7ecxjk7X44/zQ2ciDKEEL1FHsUb02CImvF5KqOQNrV/hygZl0M5uF2s9HGkZTCiPazjvGc4F200gtYk10FNUjhCOo+bYDqzGN+P/eYH+42kBgwG+NT8gmxrDiHTYHHDIFKhLo6Y6NnjdA/gWNKBBUKEiN8aclni/TRcN+4VY+vxExU2rkf4b2fn6707J4pQrDY3roq1mfcUU+qJG93aRSE9NhEB5ORckoZsRLoV+tHgJI9U5z1Oo1e80BWOyUTjfYvQTqXCo2GX2Su2dnccH8WLhCjSimTrAeZJ8UJzL8WeEd8XmshiA4Ms6PPFumjGu31qvwV2PAI5z7tBTbalUbgGaq6AFuda2RQ6uAT7IRi2zDUHOPmsAXRF59aK9rFED1iq6LiGVmOo8z2ZczfgnMdqoixZj/L8jQ2ZP7f/eG3//bb3//xid0+BjhXCFLw9Z32Pq5tTIF3QpePdVFf2ePz+Jd6n8GFL+d4MPIlghoOPWzBUe8nI52yDkaew6nVlTyDKUdqegaSS9U9A5HFOp+BzEzFz+DqwdqfgdxCFdBA4lA90EBsvjJoIHCkRuhZckW10ED4YN3QQO5ABdFA6lAt0UDstaqKXsM4PEdgC9bXkVtD3Pw0ybKbt94qPHPkXlLE4GPOFsE9xeJCCEmFWjVcncmUiAgRYiROwtFUrxCsgOsVQyzl4nwhfj+yeEtJLbfmESM7K5NsrBs+YlyPd4wGIYYGQ0AEQsWahshOdFEhSpDQwJtZi++lnj76nu9CUF49RnzPG5pzxnuFS1lk0euen5sDRcneqv3E4tPY+RQlv8UeTD32T6tmZpaD1cyrgT9tNfObAD+lRAvIi1kFPNRwBHyfNsiay8wDNpkxOi4pU+KuCgRbV9mXWrJNKTTyMENM0hxVFXJhfFA/CC4RGLitOAIw/eeM+5RxLtl5u6oOEhBNHhtbPWLbysyo+sxTNxHfWFdsB2UqTnGlVCmGbCL+yRK5dX/aHwwJ1D9Gdo5j5V7HE5U+a8j3KP0C5mpN4Snx2KarlxiWapLKoERwoFlnzRJbapyDiGuw50we0GI3HKyNGM6RpQejyQdLCXp+zmhPo6WfALZVjg6AvVK1/8nBHgWiP605IAS/3Bzgrd5vAnoaO5/mgNcF/EfH+T+xj0C0OdBHsH5PTttH8GZ78ootB85RONBysH4rTtty8GZb8RrdCb2680B3AvCeSZfrmXT5absT3mwPXqmRgdWBRob1m3DaRoY324SfueeBhd2BngdAPZPa0XNljCfteXgz+F+rPYJ9IHegPWL9Rpy2PeLNNuIVOik8h3Cgk2L9Fpy2k+LNtuC1mi4AKh9ouvCWZmI1monVTtt08Wb78PP3Z5j9HTAjr0AzqQmaSU2ctj/jzXbgFVs5tJkGCuNWjtVbcdpWjrfailfu+gCz8Ye6PqyZCduMPreujzfbjVdrEPF6Uuk0aRBZvRGnbRB5s414pV4SBw091EsCTzKzDfbceknebBteq+3EaseH2k5W78Np207ebB/Wd6h8rQskbdeYJeXG3no3b1gFaGcqA+3cKwS8gJ+GWnDbzfnGUlLJzjTwVwRuuWobM7it1sUp1VRgSyoErz221pxf1nu+eWWp2pXW5bPDpM11N+8FaEfcAygRwmQdXLHUi2IlxcJUyu5GtE6wQP2tG7bYXtrNqSXmUms08Qxj5pleoJ8ENfeczv9DPQv1XGvVUslJWPPkjK0fp4L6tCGsegbqmbc9tV6+w0VZptZpDPna8F2aycVWKfQkhc+u1xrHEENo5GoR54VsrCGF84N6r09tsZFpVf+HCTRpZArDpiU/08jkZxqZsExXFZi5UTl6k2CuLUXQ+hwqDLhHIGvFpGiKE59rr962raeCVOUW+JxU+ljT31IFG/OqSio1xrtPG3YizFB2O/fIy1pnqmJTY6+Wxx9ZWoBYzE2YKovSFlxROZMkq4Ao1rT+jJjAHK0/o0z/fAflEsh6jfGwNEli9mkDBf7yFg2ZGxs1NZGDf40RLARxaDOIfGIz4poEb3AnLaSYIxUosK4+CmuEqooThZTE1DPKnR1oR11sAlnFPtzEJXo96oMMfgZpv480VYSSWWXRjCgoqYiAJrUsQL2mrG1oBZi71Jh0T+yrQDGpFm0sNedyRuZjtrd3sfTYr3o86N0kzu/zXlLqnRKCyeSzjTDiDsprFEF/XQ6KQ1FeGvBPRLWYUip8o0k9HRk8BGHezxRlfRjl/gx0VeGf02N2Z4aUY32tZQvF1RgANfweG19N1eRtLaU3WBdbYboZu0ChxeooVp97pU6svdZStDtLlA9DDMu4KkLvGfSRXe7zXtAzZkJ20XqopnFMMPcsjDiwk2enIF6g3SEm6+H3qjWh+OKhvwW0BOTunHrz5hv5F9unVwXgDnxh0j6t7UtaIDU8XbbEvVQ4R0nal+yTx/pL60WsMOT9eSo7byTaYnKu0rAI3BjGNJ8nzAsYr3w9tWZ1oBnPevb7Kvx1bNiM9+2v//O7P2weG1S+/d0f914s8e/f/vZ3//rdf++N/8cfvvuv3/z+29//+jd7lzqOww66/vfl14BsOl7/WvOnxxaNyZX9Dr7d8H7P3m7401WZG7vs3Y97F8aD59OcNfuGjKW4yndHsSYNNqkqeZw4VIuZ3nqe6a0POG05415isAVBrMvVwJSmFg1CVF0qV4Nzx4wQSyWvTKw4jgogZKrWn1GH1hzO7w+fhCXqhGh/VWnP9B1afd764/q0B4VbgfljBewb6wCSZBUJJtgIBhWsiyIIaltuuURE1SU7lV1RzoKwnlPKZnYP5q3NkhsKRKsa8SfVPLt5A5xpBnuawV6V4pvnouHuyWddORbVS1WqLQx65ZWCRSYcDleDr5C1yQoUPzN2INQzx37Roi+pPkjnCviVm/RV7Oa9AP5guSTWFFmcwx2Flr3RTSOaoFayCo2Ci5R3JT2mmAo7lIKWwDYjcDh31R97zaWkJak12R3Q2bG52c0b4GtmMsRmJkOMu9JJVZ1cDKKJSn/qGkwjBNy25kjGQcNDS6qXFVYFox/Yd8Nva60UfgGY7zOT5bIEtSoVMS2i7fNegD0oLzS99ndhp1ATs47J9Zi5eG+8bgnhcUAc1xDlmey8ByQ+wWlIdq6Q+iVgP8P+lujOurRmsOOuCssv0nsHWqMTFp+0ltwEAPfHIRkuoAfoMZbWMix8TwfBuDB2QXrooXLo7ib/ErBf2a+o1jyRAuJL7VwAeCaaNjPR9D9PO9cy6Ct76OwqTmnG2WX7EtB1CeDvOcTEUqxKRrWcUyqiNE5GsUFc7HkMKz3J6RFa5+QF+xNYMgzNLwH0UWy4WNwhq+phvUyKzvq8F+AeUqHcWFRsJXpTW6sF+Jpu4W1T3gSJyWpwR206j/FwvB7Mv2dHjcT8C8F9EmovPvj2tAr8yUPC3bwXRLLcvNT+yrcsSjj1wj6F6JZdjhl0J+YAQ5QSyL41vTUpJOUaN2OqSz6G8ksAfxXw0LJVWr+XMA1jrV/7GBzRUVOFk+8v8MzBOymNKiXG7WEwaSqqOs06RVEO2u+KsPUSVKqi/BlZm5/5raUL+xOCXdVNbcfbEwY51f7GTzvzFlC7//QrJW9aS4x/CRY+SU7cCMEUXHBrNrbguiVzrmkD0+VsxDGCV2jOgBnVM7JJc6+AXXK1qyIqGOYxxFa96Hl5ZmIOKftiUn+Viw1RK4JfNVp6vXdD9GQ0VdtA+vvbQCN7iuCaIVKo59SOMn6f7t9xk/lDvPm+lsu7eN9fQLL085+rEtzAUI/eNsfvEMIGNfczlQs/Xfn8C4wV4MemmnjnsYUS4Vp9lIR4CranDX9t891x6eFvS64QH/3E37sLHRJYrRTFjYvGoSqpqUz96VELIct4MUelx4s5Kj5dDPyZGANzUUEnIaSdcxqnHEY4inGTxRyTnizmmPhkMRSysSA/usLbZHHaJYRa8AIwlUZaGS/mqPR4MUfFJ4sBubamwBtR5WCKJVOFesMYU5Na9XgxR6XHizkqPlkMfKmBrdCecRHcuzrKhVWxPT3jw2SbjkqPF3NUfLqYH/HbtSukJ4v5UT+YuZN3VD0rcd5lpU1/C4VtIG+gbE3nvcUclt5bzGHxvcVUw9LrzBA7MQy7YOUKf2ffH4+Y6WKOSE8Xc0R8uhhYbqzX97Aig+t6/djjFajXaNF0McekJ4s5Jj5ZjMNxh0JhoX39PrKyxiOyVCBHoHoTnTkqPV7MUfHpYnp2MlkLP+usU937lhKoinNExNPFHJOeLOaY+HQxnW6FBn33kVJpqb802ULZis3N64k7OCo9Wcwx8clieqkkvFl/b4tWNZUMWtvfPgeq11qUiQU+Kj1ezFHx6WJAL2GpSxKtYnXZ9QeZ2onu7z6ObeK1j0pPFnNMfLqYrlYJFJdBgiQZ1xCsgNwDyprETnTmqPRkMcfEJ4sRHHrVisqF+lt2am4lqKKM42otkR0v5qj0eDFHxSeLSaa5nCVzgY3ur0RGKIeDlzxB3XKcLOao9HgxR8Uni8m6wGvBcQRrdDA4cl7FiOi1t2nUGsaLOSo9XsxR8cliihWctv4umBBbf7286dEhOxWij6FOvPZR6fFijopPFtMQr9TecBqlsom9WQhRBuFOVDA1+PFijkqPF3NUfLqY7FNBZA/ileBeo2NlomJLuqX+GpbJYo5JTxbTEJ+ywP73dudiPKhDiIikTNFSysRuHJX+kR8+utOf87fEX1YnZLzIsE5IxnVCxwvrn4KoL/Gh2ZDSovTGQul3r4flEPqPJgUKOKx218Vvooudcz9O4Y0WgwhkE6ChATGkNqqYDL7psljsp2FnrM96OIV0T6lsslfWMVwo15RsYdKp4rKOsAk6R/c8xW4UKVGy6T0bIWANupeSRRzNrAO+p2gM1lxGU4zB7WyAj7LQXMRwwWfmTP2FuMntntoXsaMprMjQhpJKQKNWVyrMN1F/gYpY39uFU7Ojb1n7SzCvVYeE4Pzv//IPwGE0ow=='

def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(rows):
        value={}
        for k,v in rows:
            need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def metadata(s):
    return [getattr(s,k) for k in META]


def parent_fd(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and 2<=len(path.parts)<=64,'bounded absolute path')
    if path.parts[:4]==('/','proc','1','root'):
        fd=os.open(ANDROID,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[4:]
    else:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);parts=path.parts[1:]
    need(parts,'original leaf required')
    try:
        for name in parts[:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise


def read_original(path,maximum=16*1024*1024,expected=None,expected_metadata=None):
    global READ_BYTES
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o600 and 0<=before.st_size<=maximum,
                 'bounded private original shape')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(before.st_size+1)
            named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            need(len(raw)==before.st_size and metadata(before)==metadata(os.fstat(fd))==metadata(named),
                 'original full9 read changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'bytes':len(raw),'sha256':sha(raw),'metadata':metadata(before)}
    if expected is not None:need((len(raw),row['sha256'])==expected,'exact original pin differs')
    if expected_metadata is not None:need(row['metadata']==expected_metadata,'fixed original metadata differs')
    if str(path) in READSET:need(row==READSET[str(path)],'bootstrap original changed across verification')
    else:
        READ_BYTES+=len(raw);need(READ_BYTES<=16*1024*1024,'bootstrap original readset bound')
        READSET[str(path)]=row
    return raw


def read_directory(path):
    path=Path(path);parent,leaf=parent_fd(path)
    try:
        fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd);names=sorted(os.listdir(fd))
            need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==0
                 and stat.S_IMODE(before.st_mode)==0o700 and len(names)<=128,'private bounded source directory')
            need(metadata(before)==metadata(os.fstat(fd))==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'source directory changed')
        finally:os.close(fd)
    finally:os.close(parent)
    row={'path':str(path),'metadata':metadata(before),'names':names}
    if str(path) in DIRECTORIES:need(row==DIRECTORIES[str(path)],'source directory changed across verification')
    else:DIRECTORIES[str(path)]=row
    return row


def boot():
    with open('/proc/sys/kernel/random/boot_id','rb') as stream:raw=stream.read(128)
    need(raw.strip().decode()==BOOT,'actual boot changed');return raw


def recheck_bootstrap():
    for row in list(READSET.values()):
        read_original(row['path'],max(1,row['bytes']),(row['bytes'],row['sha256']),row['metadata'])
    for row in list(DIRECTORIES.values()):read_directory(row['path'])


def own_fds():
    names=os.listdir('/proc/self/fd');need(len(names)<=256,'own FD census bound')
    value={}
    for name in names:
        need(name.isdigit(),'own FD name shape');fd=int(name)
        try:s=os.fstat(fd)
        except OSError as error:
            need(error.errno in (errno.EBADF,errno.ENOENT),'own FD observation unknown');continue
        value[fd]=(s.st_dev,s.st_ino,s.st_mode)
    return value


def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8')

def descriptor_table():
    need(type(DESCRIPTOR_ZLIB_BASE64) is str and len(DESCRIPTOR_ZLIB_BASE64)<=4*((16384+2)//3),
         'bounded fixed descriptor encoding required')
    compressed=base64.b64decode(DESCRIPTOR_ZLIB_BASE64,validate=True)
    need(base64.b64encode(compressed).decode('ascii')==DESCRIPTOR_ZLIB_BASE64
         and (len(compressed),sha(compressed))==DESCRIPTOR_ZLIB_PIN and len(compressed)<=16384,
         'exact compressed descriptor pin required')
    decoder=zlib.decompressobj()
    raw=decoder.decompress(compressed,65537)
    need(len(raw)<=65536 and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
         'one complete bounded descriptor stream required')
    need((len(raw),sha(raw))==DESCRIPTOR_TABLE_PIN,'exact uncompressed descriptor pin required')
    table=strict(raw.decode('utf-8'))
    need(type(table) is dict and set(table)=={'added_entries','changed_parent_entries'},'exact descriptor table fields')
    added=table['added_entries'];parents=table['changed_parent_entries']
    need(type(added) is list and len(added)==76 and type(parents) is list and len(parents)==2,
         'exact 76 additions and two changed parents')
    paths=[];files=[];directories=[]
    for item in added+parents:
        need(type(item) is dict and set(item)=={'path','observed'},'exact pinned observed row')
        path=item['path'];row=item['observed']
        need(type(path) is str and str(Path(path))==path and Path(path).is_absolute()
             and '..' not in Path(path).parts and path not in paths,'canonical unique observed path')
        paths.append(path)
        need(type(row) is dict and type(row.get('metadata')) is list and len(row['metadata'])==9
             and all(type(value) is int for value in row['metadata']),'full9 observed row required')
        meta=row['metadata']
        if row.get('kind')=='file':
            need(item in added and set(row)=={'kind','metadata','bytes','sha256'}
                 and type(row['bytes']) is int and 0<=row['bytes']<=65536
                 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
                 and meta[2]==stat.S_IFREG|0o600 and meta[3:6]==[0,0,1] and meta[6]==row['bytes'],
                 'exact bounded regular file row required')
            files.append(item)
        else:
            need(row.get('kind')=='directory' and set(row)=={'kind','metadata','names'}
                 and type(row['names']) is list and len(row['names'])<=128
                 and all(type(name) is str and name not in ('.','..') and '/' not in name and '\x00' not in name
                         for name in row['names']) and row['names']==sorted(set(row['names']))
                 and meta[2]==stat.S_IFDIR|0o700 and meta[3:5]==[0,0],
                 'exact private directory names and full9 required')
            directories.append(item)
    client_transport=str(CLIENT/(CLIENT_NONCE+'.transport-r6'))
    expected_added_dirs={str(RUN),str(RUN/'capture-originals'),str(RUN/'root-setup-originals'),client_transport}
    need({item['path'] for item in added if item['observed']['kind']=='directory'}==expected_added_dirs,
         'exact four added directory paths required')
    need({item['path'] for item in parents}=={str(CLIENT),str(RUN.parent)}
         and all(item['observed']['kind']=='directory' for item in parents),'exact two changed parent directories')
    allowed_client_files={str(CLIENT/(CLIENT_NONCE+'.claim.json')),str(CLIENT/(CLIENT_NONCE+'.result.json'))}
    for item in files:
        path=item['path']
        need(path.startswith(str(RUN)+'/') or path.startswith(client_transport+'/') or path in allowed_client_files,
             'file outside fixed component/client additions')
    need(len(files)==72 and len(directories)==6
         and sum(item['observed']['bytes'] for item in files)==165391,'exact raw file count and total bytes')
    for item in added:
        parent=str(Path(item['path']).parent)
        matches=[directory for directory in directories if directory['path']==parent]
        need(len(matches)==1 and Path(item['path']).name in matches[0]['observed']['names'],
             'every added entry bound to one pinned immediate parent')
    for item in directories:
        if item['path'] in expected_added_dirs:
            need({Path(row['path']).name for row in added if str(Path(row['path']).parent)==item['path']}
                 ==set(item['observed']['names']),'complete added directory child set required')
    return table,files,directories

def collect_directory(item):
    observed=read_directory(item['path'])
    need(observed=={'path':item['path'],'metadata':item['observed']['metadata'],'names':item['observed']['names']},
         'pinned observed directory changed before collection')
    return {'path':item['path'],'kind':'directory','metadata':observed['metadata'],'names':observed['names']}

def fixed_boundary_observation(path,expected_kind):
    need((path,expected_kind) in ((BOUNDARY_PATHS[0],'file'),(BOUNDARY_PATHS[1],'directory')),
         'only two fixed native boundary leaves may be observed')
    parent,leaf=parent_fd(path)
    parent_before=None;leaf_before=None;absent=False
    try:
        parent_before=os.fstat(parent)
        need(stat.S_ISDIR(parent_before.st_mode) and parent_before.st_uid==parent_before.st_gid==0
             and stat.S_IMODE(parent_before.st_mode)==0o700,'private existing fixed boundary parent required')
        try:leaf_before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError as exc:
            need(exc.errno==errno.ENOENT,'exact boundary leaf ENOENT required');absent=True
        if absent:
            result={'path':path,'state':'ENOENT','leaf_errno':errno.ENOENT,'parent_metadata':metadata(parent_before)}
        elif expected_kind=='file':
            need(stat.S_ISREG(leaf_before.st_mode),'fixed boundary JSON is not a regular file')
            raw=read_original(path,BOUNDARY_FILE_LIMIT,expected_metadata=metadata(leaf_before))
            result={'path':path,'state':'REGULAR_ORIGINAL_RETAINED','kind':'file',**READSET[path],
                    'encoding':'base64','data_base64':base64.b64encode(raw).decode('ascii'),
                    'parent_metadata':metadata(parent_before)}
        else:
            need(stat.S_ISDIR(leaf_before.st_mode),'fixed boundary original directory is not a directory')
            row=read_directory(path)
            need(row['metadata']==metadata(leaf_before),'fixed boundary directory identity changed')
            result={'state':'DIRECTORY_NAMES_OBSERVED_NO_CHILD_READS','kind':'directory',**row,
                    'parent_metadata':metadata(parent_before)}
        need(metadata(parent_before)==metadata(os.fstat(parent)),'fixed boundary parent changed during read')
        if absent:
            try:os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'boundary leaf absence unknown')
            else:raise ValueError('fixed boundary leaf appeared during observation')
        else:
            need(metadata(leaf_before)==metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                 'fixed boundary leaf changed during observation')
    finally:os.close(parent)
    fresh_parent,fresh_leaf=parent_fd(path)
    try:
        need(fresh_leaf==leaf and metadata(os.fstat(fresh_parent))==metadata(parent_before),
             'fixed boundary canonical parent changed')
        if absent:
            try:os.stat(fresh_leaf,dir_fd=fresh_parent,follow_symlinks=False)
            except FileNotFoundError as exc:need(exc.errno==errno.ENOENT,'canonical boundary leaf absence unknown')
            else:raise ValueError('fixed boundary canonical leaf appeared')
        else:
            need(metadata(os.stat(fresh_leaf,dir_fd=fresh_parent,follow_symlinks=False))==metadata(leaf_before),
                 'fixed boundary canonical leaf changed')
    finally:os.close(fresh_parent)
    return result

def main():
    started=time.monotonic();started_unix_ns=time.time_ns()
    phase='fixed_descriptor_admission';failure=None;complete=False
    file_originals=[];directory_originals=[];boundaries=[];fd_observation=None
    read_bookends_complete=False;boundary_bookends_complete=False;boot_bookends_complete=False
    before=None;table=None
    try:
        need(len(sys.argv)==1,'fixed collector accepts no alternate paths or inputs')
        need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==0,'actual Root credentials required')
        table,files,directories=descriptor_table()
        before=own_fds();boot_raw=boot()
        phase='initial_six_exact_directory_rows'
        for item in sorted(directories,key=lambda row:(len(Path(row['path']).parts),row['path'])):
            directory_originals.append(collect_directory(item))
        phase='exact_72_original_file_bytes'
        for item in files:
            row=item['observed'];raw=read_original(item['path'],max(1,row['bytes']),
                (row['bytes'],row['sha256']),row['metadata'])
            file_originals.append({'kind':'file',**READSET[item['path']],'encoding':'base64',
                                   'data_base64':base64.b64encode(raw).decode('ascii')})
        need(len(file_originals)==72 and sum(row['bytes'] for row in file_originals)==165391,
             'complete 72 file collection required')
        phase='fixed_902_boundary_leaf_observations'
        for path,kind in zip(BOUNDARY_PATHS,('file','directory')):
            boundaries.append(fixed_boundary_observation(path,kind))
        phase='complete_read_bookends'
        recheck_bootstrap();read_bookends_complete=True
        for original,kind in zip(boundaries,('file','directory')):
            need(fixed_boundary_observation(original['path'],kind)==original,'fixed boundary observation changed at end')
        boundary_bookends_complete=True
        need(boot()==boot_raw,'boot changed across fixed collection');boot_bookends_complete=True
        complete=True;phase='complete'
    except BaseException as exc:
        failure={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':phase}
    finally:
        if before is not None:
            try:
                after=own_fds()
                remaining=[{'fd':fd,'identity':list(identity)} for fd,identity in after.items()
                           if fd>=3 and before.get(fd)!=identity]
                fd_observation={'complete':not remaining,'new_read_FDs_remaining':remaining,
                                'collector_closed_unknown_or_foreign_FDs':False}
                if remaining:
                    complete=False
                    if failure is None:failure={'type':'ValueError','detail':'new read FDs remain','phase':'FD_bookend'}
            except BaseException as exc:
                complete=False;fd_observation={'complete':False,'error_type':type(exc).__name__,'detail':str(exc)[:1024]}
                if failure is None:failure={'type':type(exc).__name__,'detail':str(exc)[:2048],'phase':'FD_bookend'}
    result={'schema':'hepta.native-guard.fixed-external-additions-observation.v1',
        'state':'FIXED_ADDITIONS_ORIGINALS_RETAINED' if complete else 'FIXED_ADDITIONS_FAILED_OR_PARTIAL_RETAIN_ORIGINALS',
        'observation_complete':complete,'failure':failure,'boot_id':BOOT,
        'fixed_external_label':EXTERNAL_LABEL,'fixed_external_nonce':EXTERNAL_NONCE,'client_nonce':CLIENT_NONCE,
        'component_run_path':str(RUN),'prior_scan_reference':PRIOR_SCAN_REFERENCE,
        'observed_inventory_reference':OBSERVED_INVENTORY_REFERENCE,'external_root_plan_reference':EXTERNAL_ROOT_PLAN_REFERENCE,
        'descriptor_table_pin':{'bytes':DESCRIPTOR_TABLE_PIN[0],'sha256':DESCRIPTOR_TABLE_PIN[1]},
        'fixed_expected_counts':{'added_regular_files':72,'added_directories':4,'changed_parent_directories':2,
                                 'added_file_bytes':165391,'boundary_leaves':2},
        'file_originals':file_originals,'directory_originals':directory_originals,'boundary_observations':boundaries,
        'actual_file_count':len(file_originals),'actual_file_bytes':sum(row['bytes'] for row in file_originals),
        'read_bookends_complete':read_bookends_complete,'boundary_bookends_complete':boundary_bookends_complete,
        'boot_bookends_complete':boot_bookends_complete,'owned_read_fd_observation':fd_observation,
        'all_read_original_descriptors':list(READSET.values()),'all_read_directory_rows':list(DIRECTORIES.values()),
        'observation_started_unix_ns':started_unix_ns,'observation_ended_unix_ns':time.time_ns(),
        'total_wall_seconds':time.monotonic()-started,'output_limit_bytes':OUTPUT_LIMIT,
        'fresh_later_collection_not_original_failed_stage_snapshot':True,
        'label_is_retained_host_plan_reference_not_inferred_qualification':True,
        'boundary_contents_not_validated_as_native_history':True,'boundary_directory_children_not_read':True,
        'writer_identity_attributed':False,'global_clearance_proof':False,'admission_granted':False,
        'component_qualified':False,'native_boundary_adopted':False,'automatic_retry':False,
        'runtime_modules_loaded':0,'runtime_function_calls':0,'locks_acquired':0,
        'phone_case_or_source_writes':0,'process_launches':0,'signals':0,'model_requests':0,
        'native_sends':0,'new_nonces':0,'lease_changes':0,'boundary_publications':0,'fixture_attempts':0}
    try:
        raw=encoded(result);need(len(raw)<=OUTPUT_LIMIT,'full original collection exceeds eight-MiB output limit')
    except BaseException as exc:
        complete=False
        raw=encoded({'schema':result['schema'],'state':'FULL_ORIGINAL_SERIALIZATION_REFUSED',
            'observation_complete':False,'full_originals_retained':False,'type':type(exc).__name__,
            'detail':str(exc)[:1024],'fixed_external_label':EXTERNAL_LABEL,'fixed_external_nonce':EXTERNAL_NONCE,
            'global_clearance_proof':False,'admission_granted':False,'component_qualified':False,
            'native_boundary_adopted':False,'automatic_retry':False,'phone_case_or_source_writes':0})
    sys.stdout.write(raw.decode('utf-8'))
    return 0 if complete else 1

if __name__=='__main__':raise SystemExit(main())
