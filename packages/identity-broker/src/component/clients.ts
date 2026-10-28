import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { vDeploymentType, vTokenEndpointAuthMethod } from "./schema";

const { array, boolean, number, object, optional, string } = v;

const vClient = object({
  clientId: string(),
  appId: string(),
  secretHash: string(),
  tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
  redirectUri: string(),
  deploymentType: vDeploymentType,
  clientName: string(),
  softwareVersion: string(),
  createdAt: number(),
  lastSignInAt: optional(number()),
});

/** Registers one deployment of an app as a client with its single exact redirect URI. */
export const create = mutation({
  args: {
    clientId: string(),
    appId: string(),
    secretHash: string(),
    tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
    redirectUri: string(),
    deploymentType: vDeploymentType,
    clientName: string(),
    softwareVersion: string(),
    createdAt: number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (existing !== null) {
      throw new Error(`A client with id "${args.clientId}" already exists`);
    }
    await ctx.db.insert("clients", {
      clientId: args.clientId,
      appId: args.appId,
      secretHash: args.secretHash,
      tokenEndpointAuthMethod: args.tokenEndpointAuthMethod,
      redirectUri: args.redirectUri,
      deploymentType: args.deploymentType,
      clientName: args.clientName,
      softwareVersion: args.softwareVersion,
      createdAt: args.createdAt,
    });
    return null;
  },
});

export const get = query({
  args: { clientId: string() },
  returns: v.union(vClient, v.null()),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client === null) {
      return null;
    }
    const { _id, _creationTime, ...fields } = client;
    return fields;
  },
});

export const listByApp = query({
  args: { appId: string() },
  returns: array(vClient),
  handler: async (ctx, args) => {
    const clients = await ctx.db
      .query("clients")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .collect();
    return clients
      .map(({ _id, _creationTime, ...fields }) => fields)
      .sort((a, b) => a.createdAt - b.createdAt || a.clientId.localeCompare(b.clientId));
  },
});

export const remove = mutation({
  args: { clientId: string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client !== null) {
      await ctx.db.delete("clients", client._id);
    }
    return null;
  },
});

/**
 * Deletes a client for `DELETE /register/<client_id>`, whose registration token names `appId`.
 * False when no client has this id or it belongs to another app: the endpoint answers both with
 * 404, so a token of one app learns nothing about the clients of another.
 */
export const unregister = mutation({
  args: { clientId: string(), appId: string() },
  returns: boolean(),
  handler: async (ctx, args) => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client === null || client.appId !== args.appId) {
      return false;
    }
    await ctx.db.delete("clients", client._id);
    return true;
  },
});
