def normalize_bundle_identifier(bundleId: str) -> str:
    # See https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/understanding_utis/understand_utis_conc/understand_utis_conc.html#//apple_ref/doc/uid/TP40001319-CH202-CHDHIJDE
    allowed_ascii_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
    normalized = ""
    for character in bundleId:
        if character in allowed_ascii_characters or ord(character) > 0x7f:
            normalized += character
        else:
            normalized += "-"
    return normalized
