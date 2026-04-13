import requests

def lookup_vendor(mac):

    try:

        url = f"https://api.macvendors.com/{mac}"

        response = requests.get(url)

        if response.status_code == 200:
            return response.text

    except:
        pass

    return "Unknown"