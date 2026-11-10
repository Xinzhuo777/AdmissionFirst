/* Exact-object comparisons only. No cached verdicts or dictionary version tags.
 * Complex nodes and unsupported arguments retain the Python implementation.
 * The GIL stays held throughout every comparison.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

static int tuple_edges(PyObject *actual, PyObject *expected) {
    Py_ssize_t n = PyTuple_GET_SIZE(actual);
    if (n != PyTuple_GET_SIZE(expected)) return 0;
    for (Py_ssize_t i = 0; i < n; i++)
        if (PyTuple_GET_ITEM(actual, i) != PyTuple_GET_ITEM(expected, i)) return 0;
    return 1;
}

static int dict_edges(PyObject *actual, PyObject *expected) {
    Py_ssize_t n = PyDict_Size(actual), pos = 0, i = 0;
    PyObject *key, *value;
    if (PyTuple_GET_SIZE(expected) != 2 * n) return 0;
    while (PyDict_Next(actual, &pos, &key, &value)) {
        if (key != PyTuple_GET_ITEM(expected, i++) ||
            value != PyTuple_GET_ITEM(expected, i++)) return 0;
    }
    return 1;
}

static PyObject *same_edges(PyObject *self, PyObject *args) {
    PyObject *actual, *expected;
    if (!PyArg_ParseTuple(args, "OO", &actual, &expected)) return NULL;
    if (!PyTuple_CheckExact(actual) || !PyTuple_CheckExact(expected))
        Py_RETURN_NOTIMPLEMENTED;
    return PyBool_FromLong(tuple_edges(actual, expected));
}

static PyObject *mapping_matches(PyObject *self, PyObject *args) {
    PyObject *actual, *expected;
    if (!PyArg_ParseTuple(args, "OO", &actual, &expected)) return NULL;
    if (!PyDict_CheckExact(actual) || !PyTuple_CheckExact(expected))
        Py_RETURN_NOTIMPLEMENTED;
    return PyBool_FromLong(dict_edges(actual, expected));
}

static PyObject *type_namespace_matches(PyObject *self, PyObject *args) {
    PyObject *cls, *expected;
    if (!PyArg_ParseTuple(args, "OO", &cls, &expected)) return NULL;
    if (Py_TYPE(cls) != &PyType_Type || !PyTuple_CheckExact(expected))
        Py_RETURN_NOTIMPLEMENTED;
    PyObject *dict = ((PyTypeObject *)cls)->tp_dict;
    if (dict == NULL || !PyDict_CheckExact(dict)) Py_RETURN_NOTIMPLEMENTED;
    return PyBool_FromLong(dict_edges(dict, expected));
}

/* Return errors as data so the Python owner can preserve its progress counters
 * before re-raising through its existing exception/fallback boundary.
 */
static PyObject *node_result(int ok, Py_ssize_t checked) {
    PyObject *error = Py_None;
    Py_INCREF(error);
    if (PyErr_Occurred()) {
        PyObject *type = NULL, *value = NULL, *tb = NULL;
        Py_DECREF(error);
        PyErr_Fetch(&type, &value, &tb);
        PyErr_NormalizeException(&type, &value, &tb);
        if (PyErr_Occurred() || value == NULL) {
            Py_XDECREF(type); Py_XDECREF(value); Py_XDECREF(tb);
            return NULL;
        }
        if (tb != NULL && PyException_SetTraceback(value, tb) < 0) {
            Py_XDECREF(type); Py_DECREF(value); Py_DECREF(tb);
            return NULL;
        }
        Py_XDECREF(type); Py_XDECREF(tb);
        error = value;
    }
    return Py_BuildValue("(OnN)", ok ? Py_True : Py_False, checked, error);
}

static PyObject *check_nodes(PyObject *self, PyObject *program) {
    Py_ssize_t checked = 0;
    if (!PyTuple_CheckExact(program)) {
        PyErr_SetString(PyExc_TypeError, "identity program must be an exact tuple");
        return node_result(0, checked);
    }
    for (Py_ssize_t i = 0; i < PyTuple_GET_SIZE(program); i++) {
        PyObject *row = PyTuple_GET_ITEM(program, i);
        if (!PyTuple_CheckExact(row) || PyTuple_GET_SIZE(row) != 4 ||
            !PyLong_CheckExact(PyTuple_GET_ITEM(row, 0))) {
            PyErr_SetString(PyExc_TypeError, "invalid identity program row");
            return node_result(0, checked);
        }
        long tag = PyLong_AsLong(PyTuple_GET_ITEM(row, 0));
        if (tag == -1 && PyErr_Occurred()) return node_result(0, checked);
        PyObject *value = PyTuple_GET_ITEM(row, 1);
        PyObject *expected = PyTuple_GET_ITEM(row, 2);
        PyObject *node = PyTuple_GET_ITEM(row, 3);
        checked++;
        int ok = 0;
        if (tag == 1) {
            if (!PyList_CheckExact(value) || !PyTuple_CheckExact(expected))
                return node_result(0, checked);
            Py_ssize_t n = PyList_GET_SIZE(value);
            if (n != PyTuple_GET_SIZE(expected)) return node_result(0, checked);
            ok = 1;
            for (Py_ssize_t j = 0; j < n; j++) {
                if (PyList_GET_ITEM(value, j) != PyTuple_GET_ITEM(expected, j)) {
                    ok = 0; break;
                }
            }
        } else if (tag == 2) {
            if (!PyTuple_CheckExact(value) || !PyTuple_CheckExact(expected))
                return node_result(0, checked);
            ok = tuple_edges(value, expected);
        } else if (tag == 3) {
            if (!PyDict_CheckExact(value) || !PyTuple_CheckExact(expected))
                return node_result(0, checked);
            ok = dict_edges(value, expected);
        } else if (tag == 0) {
            PyObject *result = PyObject_CallMethod(node, "unchanged", NULL);
            if (result == NULL) return node_result(0, checked);
            ok = PyObject_IsTrue(result);
            Py_DECREF(result);
            if (ok < 0) return node_result(0, checked);
        } else {
            PyErr_SetString(PyExc_ValueError, "unknown identity program operation");
            return node_result(0, checked);
        }
        if (!ok) return node_result(0, checked);
    }
    return node_result(1, checked);
}

static PyMethodDef methods[] = {
    {"same_edges", same_edges, METH_VARARGS, "Compare exact tuple element identities."},
    {"mapping_matches", mapping_matches, METH_VARARGS, "Compare exact dict ordered edge identities."},
    {"type_namespace_matches", type_namespace_matches, METH_VARARGS, "Compare a normal class namespace's edges."},
    {"check_nodes", check_nodes, METH_O, "Check every captured node, delegating complex nodes to Python."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_identity_primitives", NULL, -1, methods
};
PyMODINIT_FUNC PyInit__identity_primitives(void) { return PyModule_Create(&module); }
