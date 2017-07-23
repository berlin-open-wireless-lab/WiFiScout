import os


def parse_info(client):
    dhcpf = client["dhcp_fingerprint"]
    dhcpv = client["dhcp_vendor"]
    ua = client["user_agent"]
    mac = client["oui"] + ":00:00:00"

    return dhcpf, dhcpv, ua, mac


def get_device_api(client, api_key):
    import requests

    BASE_URL = "https://fingerbank.inverse.ca/api/v1/combinations/interogate?"

    dhcpf, dhcpv, ua, mac = parse_info(client)
    data = {"dhcp_fingerprint": dhcpf, "dhcp_vendor": dhcpv, "mac": mac, "user_agent": ua}
    url = BASE_URL + 'key=' + api_key
    r = requests.get(url, data)

    if r.status_code == 200:
        data = r.json()
    else:
        return False

    res = {"name": data["device"]["name"], "parents": {}}

    return res


def get_device_db(client, c):
    dhcpf, dhcpv, ua, mac = parse_info(client)

    # Get dhcp fingerprint id
    c.execute('SELECT id FROM dhcp_fingerprint WHERE value = "{dhcpf}"'.
              format(dhcpf=dhcpf))
    f_id = c.fetchone()[0]

    # Get dhcp vendor id
    c.execute('SELECT id FROM dhcp_vendor WHERE value = "{dhcpv}"'.
              format(dhcpv=dhcpv))
    v_id = c.fetchone()[0]

    # Get the device with combination score
    c.execute('SELECT combination.score, device.name, device.parent_id FROM combination, device \
              WHERE device.id = combination.device_id \
              AND combination.dhcp_fingerprint_id = {f_id} \
              AND combination.dhcp_vendor_id = {v_id} \
              AND user_agent_id \
              IN (SELECT id FROM user_agent WHERE value LIKE "{ua}")'.
              format(f_id=f_id, v_id=v_id, ua=ua))
    device = c.fetchone()

    res = {"name": device[1], "parents": {}}

    parents = []
    parent_id = device[2]
    while parent_id is not None:
        c.execute('SELECT device.name, device.parent_id FROM device \
                  WHERE device.id = {id}'.
                  format(id=parent_id))
        p = c.fetchone()
        parents.append(p[0])
        parent_id = p[1]

    for i, p in enumerate(parents):
        res["parents"][i] = p

    return res
