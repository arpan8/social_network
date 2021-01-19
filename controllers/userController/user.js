const Users = require("../../models/index").user;


exports.signup = async (req, res) => {
    try {
        var {
            first_name,
            last_name,
            email,
            password,
            mobile_no,
            // address,
            // username
        } = req.body;
        // if (!first_name || !last_name || !email || !password || !mobile_no || !address || !username) {
        //     return res.status(404).json({
        //         error: "All fields are required"
        //     });
        // }
        var email_exists = await Users.findOne({
            where: { email: req.body.email }
        });
        if (email_exists) {
            return res.status(404).json({
                error: "Email exists"
            });
        }
        var mobile_exists = await Users.findOne({
            where: { mobile_no: req.body.mobile_no }
        });
        if (mobile_exists) {
            return res.status(404).json({
                error: "Mobile number exists"
            });
        }

        await Users.create({
            first_name: sanitizer.escape(first_name),
            last_name: sanitizer.escape(last_name),
            email: sanitizer.escape(email),
            password: bcrypt.hashSync(password, 10),
            username: sanitizer.escape(username),
            mobile_no: sanitizer.escape(mobile_no),
        });
        res.json({
            success: true,
            message: "User created succesfully"
        });
    } catch (error) {
        console.log(error);
        return res.status(404).json({
            error: "Server problem"
        });
    }
};