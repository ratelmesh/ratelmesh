package com.ratelmesh.android.service

import com.ratelmesh.android.model.MeshState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

object MeshRuntime {
    private val mutableState = MutableStateFlow(MeshState())
    val state = mutableState.asStateFlow()

    internal fun update(transform: (MeshState) -> MeshState) {
        mutableState.value = transform(mutableState.value)
    }
}
