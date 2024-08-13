const path = require('path');

const renderWithLayout = (layout) => {
    return (req, res, next) =>{
        res.renderWithLayout = (view, params = {}) => {
            params.body = path.join(__dirname, '../views', view);
            res.render(layout, params);            
        }
        next();
    }
}

module.exports = renderWithLayout;