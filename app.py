import requests
from bs4 import BeautifulSoup  # parser
import json
from jsbn import RSAKey

#
# user defined
import config as cf

with requests.Session() as s:
    #
    # Step 1. Generate cookie.
    res = s.get(cf.NYSCEC_LOGIN_INDEX)

    #
    # Step 2. Use cookie to get S1 parameter
    res = s.post(
        cf.NYSCEC_SPLOGIN,
        cookies=res.cookies.get_dict())

    #
    # Step 3. Request keyModulus and key Exponent
    soup = BeautifulSoup(res.text, 'html.parser')
    request_payload = {
        "app_id": "nportalYonsei",
        "retUrl": cf.NYSCEC_BASE,
        "failUrl": cf.NYSCEC_BASE,
        "baseUrl": cf.NYSCEC_BASE,
        "S1": str(soup.find('input', id='S1').get('value')),
        "loginUrl": '',
        "ssoGubun": "Redirect",
        "refererUrl": cf.NYSCEC_LOGIN_INDEX,
        "a": "aaaa",
        "b": "bbbb"
    }

    res = s.post(
        cf.NYSCEC_PMSSO_SERVICE,
        request_payload)

    # Step 4. Second reqeust to index page

    ssoChallenge = res.text.split('ssoChallenge= \'')[1].split('\';')[0]
    keyModulus = res.text.split('rsa.setPublic( \'')[1].split('\',')[0]
    keyExponent = res.text.split('rsa.setPublic( \'' + keyModulus + '\', \'')[1].split('\' );')[0]

    # Generate E2 value
    jsonObj = {
        'userid': cf.NYSCEC_LOGIN_PARAM['userid'],
        'userpw': cf.NYSCEC_LOGIN_PARAM['userpw'],
        'ssoChallenge': ssoChallenge
    }

    rsa = RSAKey()
    rsa.setPublic(
        keyModulus,
        keyExponent
    )

    E2 = rsa.encrypt(json.dumps(jsonObj))

    request_payload = {
        "app_id": "nportalYonsei",
        "retUrl": cf.NYSCEC_BASE,
        "failUrl": cf.NYSCEC_BASE,
        "baseUrl": cf.NYSCEC_BASE,
        "loginUrl": '',
        "loginType": "invokeID",
        "ssoGubun": "Redirect",
        "refererUrl": cf.NYSCEC_LOGIN_INDEX,
        "E2": E2,
        "E3": "",
        "E4": "",
        "a": "aaaa",
        "b": "bbbb",
        "loginId": '',
        "loginPassword": ''
    }

    res = s.post(
        cf.NYSCEC_PMSSOAUTH_SERVICE,
        request_payload)

    soup = BeautifulSoup(res.text, 'html.parser')

    request_payload = {
        "app_id": "nportalYonsei",
        "retUrl": cf.NYSCEC_BASE,
        "failUrl": cf.NYSCEC_BASE,
        "baseUrl": cf.NYSCEC_BASE,
        "loginUrl": '',
        "E3": str(soup.find('input', id='E3').get('value')),
        "E4": str(soup.find('input', id='E4').get('value')),
        "S2": str(soup.find('input', id='S2').get('value')),
        "CLTID": str(soup.find('input', id='CLTID').get('value')),
        "refererUrl": cf.NYSCEC_LOGIN_INDEX,
        "ssoGubun": "Redirect",
        "a": "aaaa",
        "b": "bbbb"
    }

    res = s.post(
        cf.NYSCEC_SPLOGIN_DATA,
        request_payload)

    s.get(cf.NYSCEC_SPLOGIN_PROCESS)

    res = s.get("https://portal.yonsei.ac.kr/com/cnst/PropCtr/findMyGLIOList.do")
    print(res.text)
