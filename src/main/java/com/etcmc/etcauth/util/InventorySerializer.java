package com.etcmc.etcauth.util;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.PlayerInventory;
import org.bukkit.util.io.BukkitObjectInputStream;
import org.bukkit.util.io.BukkitObjectOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Serializes a {@link PlayerInventory} (main + armor + offhand + ender)
 * into a compact byte blob using Bukkit's official ConfigurationSerializable
 * pipeline. Survives version bumps as long as item NBT is forward-compatible.
 *
 * <p>Used to "freeze" the offline player's inventory when a premium
 * owner reclaims their username — the premium player then receives the
 * stored inventory on first authenticated join.
 */
public final class InventorySerializer {

    private InventorySerializer() {}

    public static byte[] serialize(Player player) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             BukkitObjectOutputStream out = new BukkitObjectOutputStream(baos)) {

            PlayerInventory inv = player.getInventory();
            ItemStack[] contents = inv.getContents();
            ItemStack[] armor    = inv.getArmorContents();
            ItemStack offhand    = inv.getItemInOffHand();
            ItemStack[] ender    = player.getEnderChest().getContents();

            out.writeInt(1);                    // schema version
            writeArray(out, contents);
            writeArray(out, armor);
            out.writeObject(offhand);
            writeArray(out, ender);
            out.writeFloat(player.getExp());
            out.writeInt(player.getLevel());
            out.writeDouble(player.getHealth());
            out.writeInt(player.getFoodLevel());

            out.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            Bukkit.getLogger().warning("[ETCAuth] Failed to serialize inventory: " + e.getMessage());
            return null;
        }
    }

    public static void apply(Player player, byte[] blob) {
        if (blob == null || blob.length == 0) return;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(blob);
             BukkitObjectInputStream in = new BukkitObjectInputStream(bais)) {

            int version = in.readInt();
            if (version != 1) {
                Bukkit.getLogger().warning("[ETCAuth] Unknown inventory blob version: " + version);
                return;
            }

            ItemStack[] contents = readArray(in);
            ItemStack[] armor    = readArray(in);
            ItemStack offhand    = (ItemStack) in.readObject();
            ItemStack[] ender    = readArray(in);
            float exp            = in.readFloat();
            int level            = in.readInt();
            double health        = in.readDouble();
            int food             = in.readInt();

            PlayerInventory inv = player.getInventory();
            inv.setContents(contents);
            inv.setArmorContents(armor);
            inv.setItemInOffHand(offhand);
            player.getEnderChest().setContents(ender);
            player.setExp(exp);
            player.setLevel(level);
            try {
                player.setHealth(Math.min(player.getMaxHealth(), Math.max(1.0, health)));
            } catch (Exception ignored) { /* attribute may differ */ }
            player.setFoodLevel(food);
        } catch (IOException | ClassNotFoundException e) {
            Bukkit.getLogger().warning("[ETCAuth] Failed to apply inventory: " + e.getMessage());
        }
    }

    private static void writeArray(BukkitObjectOutputStream out, ItemStack[] arr) throws IOException {
        out.writeInt(arr.length);
        for (ItemStack item : arr) out.writeObject(item);
    }

    private static ItemStack[] readArray(BukkitObjectInputStream in) throws IOException, ClassNotFoundException {
        int n = in.readInt();
        ItemStack[] arr = new ItemStack[n];
        for (int i = 0; i < n; i++) arr[i] = (ItemStack) in.readObject();
        return arr;
    }
}
