"""Clearly-labelled DEMO data: invented indicators only, flagged demo=True."""


def seed_demo(s):
    if any(i.get("demo") for i in s.invs.values()):
        return
    msgs = [
        ("demo-a", "URGENT: Your SBI account will be blocked today. Update KYC now http://sbi-kyc-update.top/verify and call 9000000001"),
        ("demo-b", "Dear customer your SBI a/c is suspended. Complete KYC immediately at http://sbi-kyc-update.top/login . Helpdesk +91 90000 00001"),
        ("demo-c", "आपका SBI खाता तुरंत बंद हो जाएगा। केवाईसी अपडेट करें http://sbi-kyc-update.top/hi OTP साझा करें"),
        ("demo-d", "Parcel on hold. Pay Rs 25 redelivery fee to indiapost@upi http://indiapost-redelivery.click/pay"),
        ("demo-e", "Congratulations! You won a prize. Claim reward http://hdfc-rewards-claim.xyz/claim pay processing fee to claims@ybl"),
    ]
    for who, text in msgs:
        s.investigate_message(text, who, demo=True)
    s.investigate_url("http://paypa1-secure-login.top/verify", "demo-f", demo=True)
    s.investigate_url("https://www.example.org/", "demo-g", demo=True)
