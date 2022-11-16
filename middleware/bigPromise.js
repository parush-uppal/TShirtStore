// try catch and async -await || use promise

module.exports = (fun) => (req,res,next) =>
  Promise.resolve(fun(req,res,next)).catch(next);