def correlate_assets(assets):

    unique = {}

    for asset in assets:

        mac = asset.get("mac")

        if mac not in unique:
            unique[mac] = asset
        else:
            unique[mac].update(asset)

    return list(unique.values())