const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'codewithroy22@gmail.com',
    pass: process.env.EMAIL_APP_PASSWORD // Use an app password, not your actual Gmail password in .env file
  }
});

exports.sendOTP = async (to, otp) => {
  const mailOptions = {
    from: 'codewithroy22@gmail.com',
    to: to,
    subject: 'Your OTP for CodeSpace Registration',
    text: `Your OTP is: ${otp}. It will expire in 10 minutes.`
  };

  await transporter.sendMail(mailOptions);
};