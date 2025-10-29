from key_manager import KeyManager

manager = KeyManager("secrets/keys.json", passphrase="", auto_persist=True)

# passphrase -> 암호 값
# manager.set("사이트명", "키값")
# manager.delete("사이트명") 