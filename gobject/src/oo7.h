/* oo7.h - GLib wrapper for Secret Service
 *
 * Copyright 2025 Bilal Elmoussaoui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the MIT License.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <glib.h>
#include <gio/gio.h>

G_BEGIN_DECLS

/**
 * OO7_ERROR:
 *
 * Error domain for Oo7. Errors in this domain will be from the #Oo7Error enumeration.
 */
#define OO7_ERROR (oo7_error_quark())

GQuark oo7_error_quark (void);

/**
 * Oo7Error:
 * @OO7_ERROR_FILE_HEADER_MISMATCH: File header mismatch
 * @OO7_ERROR_VERSION_MISMATCH: Version mismatch
 * @OO7_ERROR_NO_DATA: No data in file
 * @OO7_ERROR_NO_PARENT_DIR: No parent directory
 * @OO7_ERROR_GVARIANT_DESERIALIZATION: GVariant deserialization error
 * @OO7_ERROR_SALT_SIZE_MISMATCH: Salt size mismatch
 * @OO7_ERROR_WEAK_KEY: Encryption key is too weak
 * @OO7_ERROR_IO: I/O error
 * @OO7_ERROR_MAC_ERROR: MAC verification failed
 * @OO7_ERROR_CHECKSUM_MISMATCH: Checksum mismatch
 * @OO7_ERROR_HASHED_ATTRIBUTE_MAC: Hashed attribute MAC error
 * @OO7_ERROR_NO_DATA_DIR: XDG_DATA_DIR not available
 * @OO7_ERROR_TARGET_FILE_CHANGED: Target file has changed
 * @OO7_ERROR_PORTAL: Portal communication error
 * @OO7_ERROR_INVALID_ITEM_INDEX: Invalid item index
 * @OO7_ERROR_UTF8: UTF-8 encoding error
 * @OO7_ERROR_ALGORITHM_MISMATCH: Algorithm mismatch
 * @OO7_ERROR_INCORRECT_SECRET: Incorrect secret/password
 * @OO7_ERROR_PARTIALLY_CORRUPTED_KEYRING: Keyring is partially corrupted
 * @OO7_ERROR_CRYPTO: Cryptography operation failed
 * @OO7_ERROR_LOCKED: Keyring or item is locked
 * @OO7_ERROR_ZBUS: D-Bus communication error
 * @OO7_ERROR_SERVICE_ERROR: Secret Service error
 * @OO7_ERROR_DELETED: Item or collection was deleted
 * @OO7_ERROR_DISMISSED: User dismissed the prompt
 * @OO7_ERROR_NOT_FOUND: Collection not found
 * @OO7_ERROR_IS_LOCKED: Item or collection is locked (D-Bus)
 * @OO7_ERROR_NO_SESSION: No D-Bus session
 * @OO7_ERROR_NO_SUCH_OBJECT: D-Bus object does not exist
 * @OO7_ERROR_UNKNOWN: Unknown error
 *
 * Error codes for the OO7_ERROR error domain.
 */
typedef enum {
  OO7_ERROR_FILE_HEADER_MISMATCH = 1,
  OO7_ERROR_VERSION_MISMATCH = 2,
  OO7_ERROR_NO_DATA = 3,
  OO7_ERROR_NO_PARENT_DIR = 4,
  OO7_ERROR_GVARIANT_DESERIALIZATION = 5,
  OO7_ERROR_SALT_SIZE_MISMATCH = 6,
  OO7_ERROR_WEAK_KEY = 7,
  OO7_ERROR_IO = 8,
  OO7_ERROR_MAC_ERROR = 9,
  OO7_ERROR_CHECKSUM_MISMATCH = 10,
  OO7_ERROR_HASHED_ATTRIBUTE_MAC = 11,
  OO7_ERROR_NO_DATA_DIR = 12,
  OO7_ERROR_TARGET_FILE_CHANGED = 13,
  OO7_ERROR_PORTAL = 14,
  OO7_ERROR_INVALID_ITEM_INDEX = 15,
  OO7_ERROR_UTF8 = 16,
  OO7_ERROR_ALGORITHM_MISMATCH = 17,
  OO7_ERROR_INCORRECT_SECRET = 18,
  OO7_ERROR_PARTIALLY_CORRUPTED_KEYRING = 19,
  OO7_ERROR_CRYPTO = 20,
  OO7_ERROR_LOCKED = 21,
  OO7_ERROR_ZBUS = 100,
  OO7_ERROR_SERVICE_ERROR = 101,
  OO7_ERROR_DELETED = 102,
  OO7_ERROR_DISMISSED = 103,
  OO7_ERROR_NOT_FOUND = 104,
  OO7_ERROR_IS_LOCKED = 105,
  OO7_ERROR_NO_SESSION = 106,
  OO7_ERROR_NO_SUCH_OBJECT = 107,
  OO7_ERROR_UNKNOWN = 999
} Oo7Error;

#define OO7_TYPE_KEYRING (oo7_keyring_get_type ())
G_DECLARE_FINAL_TYPE (Oo7Keyring, oo7_keyring, OO7, KEYRING, GObject)

#define OO7_TYPE_ITEM (oo7_item_get_type ())
G_DECLARE_FINAL_TYPE (Oo7Item, oo7_item, OO7, ITEM, GObject)

void oo7_keyring_new (GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data);

Oo7Keyring * oo7_keyring_new_finish (GAsyncResult  *result,
                                     GError       **error);

Oo7Keyring * oo7_keyring_new_sync (GCancellable  *cancellable,
                                   GError       **error);

void oo7_keyring_unlock (Oo7Keyring          *self,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gboolean oo7_keyring_unlock_finish (Oo7Keyring    *self,
                                    GAsyncResult  *result,
                                    GError       **error);

gboolean oo7_keyring_unlock_sync (Oo7Keyring    *self,
                                  GCancellable  *cancellable,
                                  GError       **error);

void oo7_keyring_lock (Oo7Keyring          *self,
                       GCancellable        *cancellable,
                       GAsyncReadyCallback  callback,
                       gpointer             user_data);

gboolean oo7_keyring_lock_finish (Oo7Keyring    *self,
                                  GAsyncResult  *result,
                                  GError       **error);

gboolean oo7_keyring_lock_sync (Oo7Keyring   *self,
                                GCancellable *cancellable,
                                GError      **error);

void oo7_keyring_is_locked (Oo7Keyring          *self,
                            GCancellable        *cancellable,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data);

gboolean oo7_keyring_is_locked_finish (Oo7Keyring    *self,
                                       GAsyncResult  *result,
                                       GError       **error);

gboolean oo7_keyring_is_locked_sync (Oo7Keyring    *self,
                                     GCancellable  *cancellable,
                                     GError       **error);

void oo7_keyring_search_items (Oo7Keyring          *self,
                               GHashTable          *attributes,
                               GCancellable        *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer             user_data);

GList * oo7_keyring_search_items_finish (Oo7Keyring    *self,
                                         GAsyncResult  *result,
                                         GError       **error);

GList * oo7_keyring_search_items_sync (Oo7Keyring    *self,
                                       GHashTable    *attributes,
                                       GCancellable  *cancellable,
                                       GError       **error);

void oo7_keyring_create_item (Oo7Keyring          *self,
                              const gchar         *label,
                              GHashTable          *attributes,
                              GBytes              *secret,
                              gboolean             replace,
                              GCancellable        *cancellable,
                              GAsyncReadyCallback  callback,
                              gpointer             user_data);

gboolean oo7_keyring_create_item_finish (Oo7Keyring    *self,
                                         GAsyncResult  *result,
                                         GError       **error);

gboolean oo7_keyring_create_item_sync (Oo7Keyring    *self,
                                       const gchar   *label,
                                       GHashTable    *attributes,
                                       GBytes        *secret,
                                       gboolean       replace,
                                       GCancellable  *cancellable,
                                       GError       **error);

void oo7_keyring_delete (Oo7Keyring          *self,
                         GHashTable          *attributes,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gboolean oo7_keyring_delete_finish (Oo7Keyring    *self,
                                    GAsyncResult  *result,
                                    GError       **error);

gboolean oo7_keyring_delete_sync (Oo7Keyring    *self,
                                  GHashTable    *attributes,
                                  GCancellable  *cancellable,
                                  GError       **error);

void oo7_item_get_label (Oo7Item             *self,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gchar * oo7_item_get_label_finish (Oo7Item       *self,
                                   GAsyncResult  *result,
                                   GError       **error);

gchar * oo7_item_get_label_sync (Oo7Item       *self,
                                 GCancellable  *cancellable,
                                 GError       **error);

void oo7_item_set_label (Oo7Item             *self,
                         const gchar         *label,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gboolean oo7_item_set_label_finish (Oo7Item       *self,
                                    GAsyncResult  *result,
                                    GError       **error);

gboolean oo7_item_set_label_sync (Oo7Item       *self,
                                  const gchar   *label,
                                  GCancellable  *cancellable,
                                  GError       **error);

void oo7_item_get_secret (Oo7Item             *self,
                          GCancellable        *cancellable,
                          GAsyncReadyCallback  callback,
                          gpointer             user_data);

GBytes * oo7_item_get_secret_finish (Oo7Item       *self,
                                     GAsyncResult  *result,
                                     GError       **error);

GBytes * oo7_item_get_secret_sync (Oo7Item       *self,
                                   GCancellable  *cancellable,
                                   GError       **error);

void oo7_item_set_secret (Oo7Item             *self,
                          GBytes              *secret,
                          GCancellable        *cancellable,
                          GAsyncReadyCallback  callback,
                          gpointer             user_data);

gboolean oo7_item_set_secret_finish (Oo7Item       *self,
                                     GAsyncResult  *result,
                                     GError       **error);

gboolean oo7_item_set_secret_sync (Oo7Item       *self,
                                   GBytes        *secret,
                                   GCancellable  *cancellable,
                                   GError       **error);

void oo7_item_delete (Oo7Item             *self,
                      GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data);

gboolean oo7_item_delete_finish (Oo7Item       *self,
                                 GAsyncResult  *result,
                                 GError       **error);

gboolean oo7_item_delete_sync (Oo7Item       *self,
                               GCancellable  *cancellable,
                               GError       **error);

void oo7_item_get_created (Oo7Item             *self,
                           GCancellable        *cancellable,
                           GAsyncReadyCallback  callback,
                           gpointer             user_data);

guint64 oo7_item_get_created_finish (Oo7Item       *self,
                                     GAsyncResult  *result,
                                     GError       **error);

guint64 oo7_item_get_created_sync (Oo7Item       *self,
                                   GCancellable  *cancellable,
                                   GError       **error);

void oo7_item_get_modified (Oo7Item             *self,
                            GCancellable        *cancellable,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data);

guint64 oo7_item_get_modified_finish (Oo7Item       *self,
                                      GAsyncResult  *result,
                                      GError       **error);

guint64 oo7_item_get_modified_sync (Oo7Item       *self,
                                    GCancellable  *cancellable,
                                    GError       **error);

void oo7_item_is_locked (Oo7Item             *self,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gboolean oo7_item_is_locked_finish (Oo7Item       *self,
                                    GAsyncResult  *result,
                                    GError       **error);

gboolean oo7_item_is_locked_sync (Oo7Item       *self,
                                  GCancellable  *cancellable,
                                  GError       **error);

void oo7_item_unlock (Oo7Item            *self,
                      GCancellable       *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer            user_data);

gboolean oo7_item_unlock_finish (Oo7Item       *self,
                                 GAsyncResult  *result,
                                 GError       **error);

gboolean oo7_item_unlock_sync (Oo7Item        *self,
                                GCancellable  *cancellable,
                                GError       **error);

void oo7_item_lock (Oo7Item             *self,
                    GCancellable        *cancellable,
                    GAsyncReadyCallback  callback,
                    gpointer             user_data);

gboolean oo7_item_lock_finish (Oo7Item       *self,
                               GAsyncResult  *result,
                               GError       **error);

gboolean oo7_item_lock_sync (Oo7Item        *self,
                              GCancellable  *cancellable,
                              GError       **error);

void oo7_item_get_attributes (Oo7Item              *self,
                               GCancellable        *cancellable,
                               GAsyncReadyCallback  callback,
                               gpointer             user_data);

GHashTable * oo7_item_get_attributes_finish (Oo7Item       *self,
                                             GAsyncResult  *result,
                                             GError       **error);

GHashTable * oo7_item_get_attributes_sync (Oo7Item       *self,
                                           GCancellable  *cancellable,
                                           GError       **error);

void oo7_item_set_attributes (Oo7Item             *self,
                              GHashTable          *attributes,
                              GCancellable        *cancellable,
                              GAsyncReadyCallback  callback,
                              gpointer             user_data);

gboolean oo7_item_set_attributes_finish (Oo7Item       *self,
                                         GAsyncResult  *result,
                                         GError       **error);

gboolean oo7_item_set_attributes_sync (Oo7Item       *self,
                                       GHashTable    *attributes,
                                       GCancellable  *cancellable,
                                       GError       **error);

G_END_DECLS
