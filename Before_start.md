# วิธีติดตั้งและรัน VA Scanner

## สิ่งที่ต้องมี
- **Python 3.9+** — https://www.python.org/downloads/
- **Go 1.21+** — https://go.dev/dl/

> หากยังไม่ได้ติดตั้ง หรือ version เก่าเกิน installer จะโหลดและเปิด installer ให้อัตโนมัติ

---

## ครั้งแรก — ติดตั้ง

**Windows** — ดับเบิลคลิก `install.bat`

**macOS / Linux** — รันใน Terminal:
```
sh install.sh
```

installer จะ:
1. ตรวจ Python version
2. ตรวจ Go version (โหลด installer ให้ถ้าไม่มี หรือ version เก่าเกิน)
3. สร้าง virtual environment (`venv/`)
4. ติดตั้ง Python packages จาก `requirements.txt`

---

## รันทุกครั้ง

```
python start.py          # Windows
python3 start.py         # macOS / Linux
```
