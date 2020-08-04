const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');

const Mutations = {
    async createItem(parent, args, ctx, info) {
        if(!ctx.request.userId) {
            throw new Error(`You must be logged in to do that!`);
        }
        const item = await ctx.db.mutation.createItem({
            data: {
            // this is how we make a relationship between the Item and the User
            user: {
                connect: {
                    id: ctx.request.userId,
                },
            },
            ...args,
            }
        }, info);

        return item;
    },
    updateItem(parent, args, ctx, info) {
        // first, take a copy of the updates
        const updates = { ...args };
        // remove the ID from the updates
        delete updates.id;
        // run the update method
        return ctx.db.mutation.updateItem(
            {
                data: updates,
                where: {
                    id: args.id,
                },
            }, info
        );
    },
    async deleteItem(parent, args, ctx, info) {
        const where = { id: args.id };
        // 1. find the item
        const item = await ctx.db.query.item({ where }, `{ id title user { id }}`);
        // 2. check if they own that item, or have the permissions
        const ownsItem = item.user.id === ctx.request.userId;
        const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));
        if(!ownsItem && hasPermissions) {
            throw new Error("You don't have permission to do that!");
        } 
        // 3. delete
        return ctx.db.mutation.deleteItem({ where }, info);
    },
    async signup(parent, args, ctx, info) {
        // lowercase the email
        args.email = args.email.toLowerCase();
        // hash the password
        const password = await bcrypt.hash(args.password, 10);
        // create the user in the database
        const user = await ctx.db.mutation.createUser(
            {
                data: {
                    ...args,
                    password,
                    permissions: { set: ['USER', 'ADMIN']}
                }
            }, 
        info
        );

        // create the jwt token for them
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // we set the jwt as a cookie on the response
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 24 * 365, // 1 year cookie
        });
        // we return the user to the browser
        return user;
    },
    async signin(parent, { email, password }, ctx, info) {
        // 1. check if their is user with that email
        const user = await ctx.db.query.user({ where: {email }});
        if(!user){
            throw new Error(`NO such user found for email ${email}`);
        }
        // 2. Check if their password is correct
        const valid = await bcrypt.compare(password, user.password);
        if(!valid){
            throw new Error(`Invalid password`);
        }
        // 3. generate the JWT token
        const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
        // 4. set the cookie with the token
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365,
        })
        // 5. return the user
        return user;
    },
    signout(parent, args, ctx, info) {
        ctx.response.clearCookie('token');
        return { message: 'Goodbye!' };
    },
    async requestReset(parent, args, ctx, info) {
        // 1. Check if this is a real user
        const user = await ctx.db.query.user({ where: { email: args.email }});
        if(!user){
            throw new Error(`No such user found for email ${args.email}`);
        }
        // 2. set a reset token and expiry on that user
        const randomBytesPromisified = promisify(randomBytes);
        const resetToken = (await randomBytesPromisified(20)).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000;
        const res = await ctx.db.mutation.updateUser({
            where: { email: args.email },
            data: { resetToken, resetTokenExpiry }
        });
        // 3. email them the reset token
        const mailRes = await transport.sendMail({
            from: 'sickfits.com',
            to: user.email,
            subject: 'Your password reset token',
            html: makeANiceEmail(`
                Your password reset token is here! 
                \n\n 
                <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">
                Click here to reset</a>>
            `),
        });
        // 4. return the message
        return { message: 'Thanks!'};
    },
    async resetPassword(parent, args, ctx, info) {
        // check if the password match
        if(args.password !== args.confirmPassword) {
            throw new Error(`Password doesn't match!`);
        }
        // check of its a legit reset token
        // check if its expired
        const [ user ] = await ctx.db.query.users({
            where: {
                resetToken: args.resetToken,
                resetTokenExpiry_gte: Date.now() - 3600000
            }
        });
        if(!user) {
            throw new Error('This token is either invalid or expired');
        }
        // hash  their password
        const password = await bcrypt.hash(args.password, 10);
        // save the next password to t he user remove old token
        const updatedUser = await ctx.db.mutation.updateUser({
            where: { email: user.email },
            data: {
                password,
                resetToken: null,
                resetTokenExpiry: null
            }
        })
        // generate jwt
        const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
        // set the jwt cookie
        ctx.response.cookie('token', token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 365
        });
        // return the new user
        return updatedUser;
    },
    async updatePermissions(parent, args, ctx, info) {
        // 1. check if they are logged in
        if(!ctx.request.userId) {
            throw new Error('You must be logged in');
        }
        // 2. query the current users
        const currentUser = await ctx.db.query.user(
            {
                where: {
                    id: ctx.request.userId,
                }
            },
            info
        );
        // 3. check if they have permisssions to do this
        hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
        // 4. update the permissions
        return ctx.db.mutation.updateUser({
            data: {
                permissions: {
                    set: args.permissions,
                },
            },
            where: {
                id: args.userId
            },
        },
        info
        );
    },
    async addToCart(parent, args, ctx, info) {
        // 1. make sure they are signed in
        const { userId } = ctx.request;
        if(!userId){
            throw new Error('You must be signed in soon');
        }
        // 2. Query the users current cart
        const [existingCartItem] = await ctx.db.query.cartItems({
            where: {
                user:  { id: userId},
                item: { id: args.id},
            },
        });
        // 3. Check if the item is already in the cart and increment 1 if it is
        if(existingCartItem) {
            return ctx.db.mutation.updateCartItem({
                where: { id: existingCartItem.id },
                data: { quantity: existingCartItem.quantity + 1 }, 
            },
            info
            );
        }
        // 4. if its not, create a fresh cartItem fot that user
        return ctx.db.mutation.createCartItem({
            data: {
                user: {
                    connect: { id: userId },
                },
                item: {
                    connect: { id: args.id },
                },
            }
        },
        info
        );
    },
    async removeFromCart(parent, args, ctx, info) {
        // 1. find the cart item
        const cartItem = await ctx.db.query.cartItem({
            where: {
                id: args.id,
            }
        },
        `{ id, user { id }}`
        );
        // 1.5 make sure an item is found
        if(!cartItem) throw new Error('No Cart Item found!');
        // 2. make sure they own that cart item
        if(cartItem.user.id !== ctx.request.userId) {
            throw new Error('Cheating huhh?');
        }
        // 3. delete the cartitem
        return ctx.db.mutation.deleteCartItem({
            where: { id: args.id },           
        }, info);
    }
};

module.exports = Mutations;
