const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'codewithroy22@gmail.com',
    pass: process.env.EMAIL_APP_PASSWORD
  }
});

exports.sendOTP = async (to, otp) => {
  let base64Image;
  try {
    const imagePath = path.join(__dirname, '../static/completeLogo.png');
    base64Image = fs.readFileSync(imagePath, { encoding: 'base64' });
  } catch (error) {
    console.error('Error reading logo file:', error);
    // Continue without image if there's an error
  }

  const mailOptions = {
    from: 'codewithroy22@gmail.com',
    to: to,
    subject: 'Your OTP for CodeSpace Registration',
    html: `
      <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
       <!-- <img src="data:image/png;base64,${base64Image}" alt="Company Logo" style="width: 120px; margin-bottom: 20px;"> -->
        <h2 style="color: #4CAF50;">Welcome to CodeSpace!</h2>
        <p style="font-size: 16px; color: #333;">
          Your OTP is:
          <span style="font-weight: bold; font-size: 18px;">${otp}</span>
        </p>
        <p style="font-size: 14px; color: #777;">
          Please use this OTP within 10 minutes to complete your registration.
        </p>
        <div style="border-top: 1px solid #eee; margin-top: 20px; padding-top: 10px; color: #888; font-size: 12px;">
          &copy; 2024 CodeSpace Inc. All rights reserved.
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send OTP email');
  }
};