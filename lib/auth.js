module.exports = {
    isOwner:function(request, response) {
        if (request.user) {
            return true;
        } else {
            return false;
        }
    },
    statusUI:function(request, response) {
        var authStatusUI = '<a href="/login">login</a> | <a href="/register">Register</a>'
        if (this.isOwner(request, response)) {
            authStatusUI = `${request.user.phone} | <a href="/logout">logout</a>`;
        }
        return authStatusUI;
    }
}