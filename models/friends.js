'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class friends extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  };
  friends.init({
    sender_id: DataTypes.INTEGER,
    reciever_id: DataTypes.INTEGER,
    status: DataTypes.STRING,
    sentByme: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'friends',
  });
  return friends;
};