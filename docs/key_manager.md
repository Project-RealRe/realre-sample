기본 사용

KeyManager를 생성할 때 passphrase를 주면 저장 시 자동으로 암호화합니다.


from key_manager import KeyManager

manager = KeyManager(passphrase="나만의 암호문구")
manager.set("naver_api", "발급받은-키")
print(manager.get("naver_api"))  # 자동 복호화



파일로 저장/불러오기

storage_path에 JSON 저장 경로를 주고 auto_persist=True로 설정하면 값 변경마다 자동 저장됩니다.
manager = KeyManager("secrets/keys.json", passphrase="문구", auto_persist=True)
manager.set("kakao_api", "키값")        # 즉시 저장
manager.delete("kakao_api")             # 삭제 또한 저장
manager.load_from_disk()                # 강제로 재로딩




여러 키 한번에 등록

manager.bulk_set({"google": "g키", "aws": "aws키"})


환경 변수에서 가져오기 / 내보내기

# 환경 변수 -> KeyManager
manager.import_from_env({"naver": "NAVER_API_KEY", "kakao": "KAKAO_SECRET"})

# KeyManager -> 환경 변수 (기존 변수 덮어쓰기 가능)
manager.export_to_env({"naver": "NAVER_API_KEY"}, overwrite=True)



직접 암호화/복호화 도구

from key_manager import encrypt_value, decrypt_value

token = encrypt_value("원문", "passphrase")
plain = decrypt_value(token, "passphrase")