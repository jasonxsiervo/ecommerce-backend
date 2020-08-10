const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  me(parent, args, ctx, info) {
    // check if there is a current userId
    if(!ctx.request.userId){
      return null;
    }
    return ctx.db.query.user({
      where: { id: ctx.request.userId },
    }, info);
  },
  async users(parent, args, ctx, info){
    // 1. check fi they are logged in
    if(!ctx.request.userId){
      throw new Error(`You must be logged in to do that!`);
    }
    // 2. check if the user has the permissions to query all the users
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);
    // 3. If they do, query all the users
    return ctx.db.query.users({}, info);
  },
  async order(parent, args, ctx, info){
    // make sure they are signed in
    const { userId } = ctx.request;
    if(!userId) {
      throw new Error('You must be signed in to do this!');
    }
    // query the current order
    const order = await ctx.db.query.order({
        where: { id: args.id }
      }, info
    );
    // check if they have the permission to see this order
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
    if(!ownsOrder || !hasPermissionToSeeOrder) {
      throw new Error(`You can't see this bud!`);
    }
    // return the order
    return order;
  },
  async orders(parent, args, ctx, info) {
    // check if a user is signed in
    const { userId } = ctx.request;
    if(!userId) {
      throw new Error('You must be signed in to do that!');
    };
    // get all orders from that user
    const orders = ctx.db.query.orders({
        where: {
          user: { id: userId } 
        }
      },
      info
    );
    // return orders
    return orders;
  }
};

module.exports = Query;
