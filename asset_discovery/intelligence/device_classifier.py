# def classify_device(ip, ports, vendor="Unknown"):

#     port_list = ports
#     vendor_lower = vendor.lower()

#     # =========================
#     # 1️⃣ VENDOR-BASED DETECTION (PRIMARY)
#     # =========================

#     if vendor != "Unknown":

#         # Apple devices
#         if "apple" in vendor_lower:
#             return "MacOS / iOS Device"

#         # Network devices
#         if any(v in vendor_lower for v in ["cisco", "juniper", "aruba", "huawei"]):
#             return "Router / Network Device"

#         # Printers
#         if any(v in vendor_lower for v in ["hp", "canon", "epson", "brother"]):
#             return "Printer"

#         # Cameras / IoT
#         if any(v in vendor_lower for v in ["hikvision", "dahua", "axis", "tp-link", "xiaomi"]):
#             return "IoT Device (Camera/Smart Device)"

#     # =========================
#     # 2️⃣ PORT-BASED DETECTION (FALLBACK)
#     # =========================

#     # Windows (very strong indicator)
#     if 445 in port_list:
#         return "Windows Machine"

#     # Linux
#     if 22 in port_list:
#         return "Linux Machine"

#     # Routers (common services)
#     if 53 in port_list and (80 in port_list or 443 in port_list):
#         return "Router"

#     # Cameras (RTSP)
#     if 554 in port_list:
#         return "IP Camera"

#     # Printer
#     if 9100 in port_list:
#         return "Printer"

#     # Web server (LOW priority)
#     if 80 in port_list or 443 in port_list:
#         return "Web Server"

#     # =========================
#     # 3️⃣ IP-BASED HINT (VERY WEAK)
#     # =========================

#     if ip.endswith(".1"):
#         return "Possible Router"

#     # =========================
#     # 4️⃣ DEFAULT
#     # =========================

#     return "Unknown Device"


def classify_device(ip, ports, vendor="Unknown"):

    port_list = ports
    vendor_lower = vendor.lower()

    # =========================
    # 1️⃣ VENDOR-BASED DETECTION (PRIMARY)
    # =========================

    if vendor != "Unknown":

        # Apple devices
        if "apple" in vendor_lower:
            return "MacOS / iOS Device"

        # Network devices
        if any(v in vendor_lower for v in ["cisco", "juniper", "aruba", "huawei", "mikrotik", "ubiquiti", "netgear", "zyxel", "fortinet", "palo alto"]):
            return "Router / Network Device"

        # Printers
        if any(v in vendor_lower for v in ["hp", "canon", "epson", "brother", "xerox", "ricoh", "lexmark", "kyocera"]):
            return "Printer"

        # Cameras / IoT
        if any(v in vendor_lower for v in ["hikvision", "dahua", "axis", "tp-link", "xiaomi", "reolink", "amcrest", "hanwha"]):
            return "IoT Device (Camera/Smart Device)"

        # Microsoft hardware → almost always Windows
        if "microsoft" in vendor_lower:
            return "Windows Machine"

        # Dell, Lenovo, ASUS, Acer — dedicated PC/laptop OEMs
        if any(v in vendor_lower for v in ["dell", "lenovo", "asus", "acer", "toshiba", "fujitsu"]):
            if 445 in port_list:
                return "Windows Machine"
            if 22 in port_list:
                return "Linux Machine"
            return "Workstation / Laptop"

        # NIC/chipset vendors (Intel, Realtek, Broadcom, etc.)
        # These appear in ALL device types so we MUST cross-check with ports
        NIC_VENDORS = ["intel", "realtek", "broadcom", "qualcomm", "atheros", "marvell", "nvidia"]
        if any(v in vendor_lower for v in NIC_VENDORS):
            if 445 in port_list:
                return "Windows Machine"
            if 3389 in port_list:
                return "Windows Machine"
            if 22 in port_list:
                return "Linux Machine"
            if 53 in port_list and (80 in port_list or 443 in port_list):
                return "Router / Network Device"
            # No distinguishing ports — vendor alone is not enough
            return "Windows / Linux Workstation (Intel NIC)"

    # =========================
    # 2️⃣ PORT-BASED DETECTION (FALLBACK)
    # =========================

    # Windows (very strong indicator)
    if 445 in port_list:
        return "Windows Machine"

    # Linux
    if 22 in port_list:
        return "Linux Machine"

    # Routers (common services)
    if 53 in port_list and (80 in port_list or 443 in port_list):
        return "Router"

    # Cameras (RTSP)
    if 554 in port_list:
        return "IP Camera"

    # Printer
    if 9100 in port_list:
        return "Printer"

    # Web server (LOW priority)
    if 80 in port_list or 443 in port_list:
        return "Web Server"

    # =========================
    # 3️⃣ IP-BASED HINT (VERY WEAK)
    # =========================

    if ip.endswith(".1"):
        return "Possible Router"

    # =========================
    # 4️⃣ DEFAULT
    # =========================

    return "Unknown Device"