import smtplib
from email.message import EmailMessage
from otp import otp

server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()

server.login("sohan.bhatta009@gmail.com", "oppv uwip prjf foid")
to_mail = input("Enter you email: ")

from_mail = "sohan.bhatta009@gmail.com"

msg = EmailMessage()
msg["Subject"] = "Otp Verification "
msg["From"] = from_mail
msg["To"] = to_mail
msg.set_content(f"Your otp is {otp}")

server.send_message(msg)

print("Email sent")
