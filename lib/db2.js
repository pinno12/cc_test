const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')

const adapter = new FileSync('db.json')
const db2 = low(adapter)
db2.defaults({users:[]}).write();
module.exports = db2;