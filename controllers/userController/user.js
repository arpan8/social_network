const Users = require("../../models/index").user;
const Friends = require("../../models/index").friends;
const bcrypt = require('bcrypt');
const sequelize = require('sequelize');
const Op = sequelize.Op;

exports.signup = async (req, res) => {
    try {
        var {
            first_name,
            last_name,
            email,
            password,
            mobile_no,
        } = req.body;
        var email_exists = await Users.findOne({
            where: { email: req.body.email }
        });
        if (email_exists) {
            return res.status(200).json({
                error: "Email exists"
            });
        }
        var mobile_exists = await Users.findOne({
            where: { mobile_no: req.body.mobile_no }
        });
        if (mobile_exists) {
            return res.status(200).json({
                error: "Mobile number exists"
            });
        }

        await Users.create({
            first_name: first_name,
            last_name: last_name,
            email: email,
            password: bcrypt.hashSync(password, 10),
            mobile_no: mobile_no,
        });
        res.json({
            success: true,
            message: "User created succesfully"
        });
    } catch (error) {
        throw error
    }
};

exports.search = async (req, res) => {
    try {
        var whereCondition = {};
        if (req.body.last_name) {
            whereCondition.last_name = req.body.last_name
        }
        if (req.body.first_name) {
            whereCondition.first_name = req.body.first_name
        }
        var user = await Users.findAll({
            where: whereCondition,
            attributes: ['id', 'first_name', 'last_name']
        });
        res.json({
            user: user.length === 0 ? "No users found" : user
        })
    } catch (error) {
        throw error
    }
}

exports.sendfriendreq = async (req, res) => {
    try {
        await Friends.create({
            sender_id: req.user.id,
            reciever_id: req.body.id,
            status: 'Pending',
            sentByme: "yes"
        });
        res.json({
            message: "Request sent"
        })
    } catch (error) {
        throw error
    }
}

exports.acceptrequest = async (req, res) => {
    try {
        //console.log(req.user.id)
        await Friends.update({
            status: 'Accepted'
        }, {
            where: {
                sender_id: req.body.id,
                reciever_id: req.user.id
            }
        });
        res.json({
            mesagge: "Request accepted"
        })
    } catch (error) {
        throw error
    }
}

