/*
 * Tests for oo7 GObject bindings
 */

#include <glib.h>
#include <gio/gio.h>
#include "../src/oo7.h"
#include <string.h>

static void
test_basic_operations (void)
{
    g_autoptr (GError) error = NULL;
    g_autoptr (Oo7Keyring) keyring = NULL;
    g_autoptr (GHashTable) attributes = NULL;
    g_autoptr (GList) items = NULL;
    g_autoptr (Oo7Item) item = NULL;
    g_autofree gchar *label = NULL;
    g_autoptr (GHashTable) attrs = NULL;
    g_autoptr (GBytes) secret = NULL;
    const guint8 *secret_data;
    gsize secret_len;
    guint64 created, modified;
    gboolean is_locked;

    /* Create keyring */
    keyring = oo7_keyring_new_sync (NULL, &error);
    g_assert_no_error (error);
    g_assert_nonnull (keyring);

    /* Check is_locked */
    is_locked = oo7_keyring_is_locked_sync (keyring, NULL, &error);
    g_assert_no_error (error);
    g_test_message ("Keyring is_locked: %d", is_locked);

    /* Create an item */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-c-test"));
    g_hash_table_insert (attributes, g_strdup ("username"), g_strdup ("alice"));
    g_hash_table_insert (attributes, g_strdup ("service"), g_strdup ("example.com"));

    {
        g_autoptr (GBytes) secret_bytes = g_bytes_new_static ("my-secret-password", 18);
        gboolean result = oo7_keyring_create_item_sync (
            keyring,
            "Test Password",
            attributes,
            secret_bytes,
            TRUE,  /* replace */
            NULL,
            &error
        );
        g_assert_no_error (error);
        g_assert_true (result);
    }

    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Search for items */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-c-test"));

    items = oo7_keyring_search_items_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_nonnull (items);
    g_assert_cmpint (g_list_length (items), ==, 1);

    /* Get item properties */
    item = g_object_ref (items->data);

    label = oo7_item_get_label_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (label, ==, "Test Password");
    g_clear_pointer (&label, g_free);

    attrs = oo7_item_get_attributes_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (g_hash_table_lookup (attrs, "application"), ==, "oo7-c-test");
    g_assert_cmpstr (g_hash_table_lookup (attrs, "username"), ==, "alice");
    g_assert_cmpstr (g_hash_table_lookup (attrs, "service"), ==, "example.com");
    g_clear_pointer (&attrs, g_hash_table_unref);

    secret = oo7_item_get_secret_sync (item, NULL, &error);
    g_assert_no_error (error);
    secret_data = g_bytes_get_data (secret, &secret_len);
    g_assert_cmpint (secret_len, ==, 18);
    g_assert_cmpmem (secret_data, secret_len, "my-secret-password", 18);
    g_clear_pointer (&secret, g_bytes_unref);

    created = oo7_item_get_created_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (created, >, 0);

    modified = oo7_item_get_modified_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (modified, >, 0);
    g_assert_cmpint (modified, >=, created);

    is_locked = oo7_item_is_locked_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_test_message("Item is_locked: %d", is_locked);

    g_clear_pointer (&item, g_object_unref);
    g_list_free_full (items, g_object_unref);
    items = NULL;
    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Delete items */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-c-test"));
    gboolean result = oo7_keyring_delete_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_true (result);
}

static void
test_item_mutations (void)
{
    g_autoptr (GError) error = NULL;
    g_autoptr (Oo7Keyring) keyring = NULL;
    g_autoptr (GHashTable) attributes = NULL;
    g_autoptr (GList) items = NULL;
    g_autoptr (Oo7Item) item = NULL;
    g_autofree gchar *label = NULL;
    g_autoptr (GHashTable) attrs = NULL;
    g_autoptr (GBytes) secret = NULL;
    const guint8 *secret_data;
    gsize secret_len;
    gboolean result;

    keyring = oo7_keyring_new_sync (NULL, &error);
    g_assert_no_error (error);

    /* Create item */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-mutation-test"));
    g_hash_table_insert (attributes, g_strdup ("version"), g_strdup ("1.0"));

    {
        g_autoptr (GBytes) secret_bytes = g_bytes_new_static ("original-secret", 15);
        result = oo7_keyring_create_item_sync (
            keyring, "Original Label", attributes, secret_bytes, TRUE, NULL, &error
        );
        g_assert_no_error (error);
        g_assert_true (result);
    }

    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Search for item */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-mutation-test"));
    items = oo7_keyring_search_items_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    item = g_object_ref (items->data);
    g_list_free_full (items, g_object_unref);
    items = NULL;

    /* Set label */
    result = oo7_item_set_label_sync (item, "Updated Label", NULL, &error);
    g_assert_no_error (error);
    g_assert_true (result);

    label = oo7_item_get_label_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (label, ==, "Updated Label");
    g_clear_pointer (&label, g_free);

    /* Set attributes */
    g_clear_pointer (&attributes, g_hash_table_unref);
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-mutation-test"));
    g_hash_table_insert (attributes, g_strdup ("version"), g_strdup ("2.0"));
    g_hash_table_insert (attributes, g_strdup ("new-field"), g_strdup ("new-value"));

    result = oo7_item_set_attributes_sync(item, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_true (result);

    attrs = oo7_item_get_attributes_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (g_hash_table_lookup (attrs, "version"), ==, "2.0");
    g_assert_cmpstr (g_hash_table_lookup (attrs, "new-field"), ==, "new-value");
    g_clear_pointer (&attrs, g_hash_table_unref);

    /* Set secret */
    {
        g_autoptr (GBytes) secret_bytes = g_bytes_new_static ("new-secret-value", 16);
        result = oo7_item_set_secret_sync (item, secret_bytes, NULL, &error);
        g_assert_no_error (error);
        g_assert_true (result);
    }

    secret = oo7_item_get_secret_sync (item, NULL, &error);
    g_assert_no_error (error);
    secret_data = g_bytes_get_data (secret, &secret_len);
    g_assert_cmpint (secret_len, ==, 16);
    g_assert_cmpmem (secret_data, secret_len, "new-secret-value", 16);
    g_clear_pointer (&secret, g_bytes_unref);

    /* Delete item */
    result = oo7_item_delete_sync (item, NULL, &error);
    g_assert_no_error (error);
    g_assert_true (result);

    g_clear_pointer (&item, g_object_unref);
    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Verify deletion */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-mutation-test"));
    items = oo7_keyring_search_items_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (g_list_length (items), ==, 0);
}

static void
test_multiple_items (void)
{
    g_autoptr (GError) error = NULL;
    g_autoptr (Oo7Keyring) keyring = NULL;
    g_autoptr (GHashTable) attributes = NULL;
    g_autoptr (GList) items = NULL;
    g_autofree gchar *label = NULL;
    g_autoptr (GBytes) secret = NULL;
    const guint8 *secret_data;
    gsize secret_len;
    gboolean result;

    keyring = oo7_keyring_new_sync (NULL, &error);
    g_assert_no_error (error);

    /* Create multiple items */
    for (int i = 0; i < 3; i++) {
        g_autofree gchar *item_label = g_strdup_printf ("Test Item %d", i);
        g_autofree gchar *index_str = g_strdup_printf ("%d", i);
        g_autofree gchar *secret_str = g_strdup_printf ("secret-%d", i);

        g_autoptr (GHashTable) attrs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
        g_hash_table_insert (attrs, g_strdup ("application"), g_strdup ("oo7-multi-test"));
        g_hash_table_insert (attrs, g_strdup ("index"), g_strdup (index_str));
        g_hash_table_insert (attrs, g_strdup ("group"), g_strdup ("test-group"));

        g_autoptr (GBytes) secret_bytes = g_bytes_new (secret_str, strlen (secret_str));
        result = oo7_keyring_create_item_sync (
            keyring, item_label, attrs, secret_bytes, TRUE, NULL, &error
        );
        g_assert_no_error (error);
        g_assert_true (result);
    }

    /* Search for all items */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-multi-test"));
    items = oo7_keyring_search_items_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (g_list_length (items), ==, 3);
    g_list_free_full (items, g_object_unref);
    items = NULL;
    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Search for specific item */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-multi-test"));
    g_hash_table_insert (attributes, g_strdup ("index"), g_strdup ("1"));
    items = oo7_keyring_search_items_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_cmpint (g_list_length (items), ==, 1);

    {
        g_autoptr (Oo7Item) item = g_object_ref (items->data);
        label = oo7_item_get_label_sync (item, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpstr (label, ==, "Test Item 1");
        g_clear_pointer (&label, g_free);

        secret = oo7_item_get_secret_sync (item, NULL, &error);
        g_assert_no_error (error);
        secret_data = g_bytes_get_data (secret, &secret_len);
        g_assert_cmpint (secret_len, ==, 8);
        g_assert_cmpmem (secret_data, secret_len, "secret-1", 8);
        g_clear_pointer (&secret, g_bytes_unref);
    }

    g_list_free_full (items, g_object_unref);
    items = NULL;
    g_clear_pointer (&attributes, g_hash_table_unref);

    /* Clean up */
    attributes = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_insert (attributes, g_strdup ("application"), g_strdup ("oo7-multi-test"));
    result = oo7_keyring_delete_sync (keyring, attributes, NULL, &error);
    g_assert_no_error (error);
    g_assert_true (result);
}

static void
test_cancellation (void)
{
    g_autoptr (GError) error = NULL;
    g_autoptr (GCancellable) cancellable = NULL;
    g_autoptr (Oo7Keyring) keyring = NULL;

    /* Test sync cancellation */
    cancellable = g_cancellable_new ();
    g_cancellable_cancel (cancellable);

    keyring = oo7_keyring_new_sync (cancellable, &error);
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
    g_assert_null (keyring);
    g_clear_error (&error);
    g_clear_object (&cancellable);

    /* Test successful operation with non-cancelled cancellable */
    cancellable = g_cancellable_new ();
    keyring = oo7_keyring_new_sync (cancellable, &error);
    g_assert_no_error (error);
    g_assert_nonnull (keyring);
    g_clear_object (&cancellable);
    g_clear_object (&keyring);

    /* Test cancelling during sync operation */
    cancellable = g_cancellable_new ();
    g_cancellable_cancel (cancellable);

    keyring = oo7_keyring_new_sync (NULL, &error);
    g_assert_no_error (error);
    g_assert_nonnull (keyring);

    gboolean result = oo7_keyring_unlock_sync (keyring, cancellable, &error);
    g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
    g_assert_false (result);
}

int
main (int   argc,
      char *argv[])
{
    g_test_init (&argc, &argv, NULL);

    g_test_add_func ("/oo7/basic-operations", test_basic_operations);
    g_test_add_func ("/oo7/item-mutations", test_item_mutations);
    g_test_add_func ("/oo7/multiple-items", test_multiple_items);
    g_test_add_func ("/oo7/cancellation", test_cancellation);

    return g_test_run ();
}
