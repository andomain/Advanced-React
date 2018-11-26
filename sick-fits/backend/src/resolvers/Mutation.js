const Mutations = {
    async createItem(parent, args, ctx, info) {
        // TODO: Check if they are logged in

        const item = await ctx.db.mutation.createItem({
            data: {
                ...args
            }
        }, info);

        return item;
    },
    updateItem(parent, args, ctx, info) {
        // Take a copy of the updates
        const updates = { ...args };
        // Remove ID from updates
        delete updates.id;
        // Run update method
        return ctx.db.mutation.updateItem({
            data: updates,
            where: {
                id: args.id,
            },
            info
        });
    },

    async deleteItem(parent, args, ctx, info) {
        const where = { id: args.id };
        // Find the item
        const item = await ctx.db.query.item({ where }, `{ id title }`);
        // TODO Check if they own the item or have delete permissions
        return ctx.db.mutation.deleteItem({ where }, info);
    }
};

module.exports = Mutations;
