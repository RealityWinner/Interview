- [Setup and Research](#setup-and-research)
- [Vulnerability Assesment](#vulnerability-assesment)
  - [Detaching the backing buffer](#detaching-the-backing-buffer)
  - [Heap isolate](#heap-isolate)
  - [Why is this bug a read-only UAF?](#why-is-this-bug-a-read-only-uaf)
- [PoC Development](#poc-development)
  - [Corrupted pixel data](#corrupted-pixel-data)
  - [Soft failures](#soft-failures)
  - [Arbitrary image sizes](#arbitrary-image-sizes)
- [Discovery](#discovery)
  - [Manual identification](#manual-identification)
  - [Automation patterns](#automation-patterns)
- [Future research](#future-research)

---

# Setup and Research

The provided [Project Zero #1821](https://bugs.chromium.org/p/project-zero/issues/detail?id=1821) documents a Use-After-Free inside of *audio_worklet_global_scope.cc `AudioWorkletGlobalScope::Process()`*. A basic [poc](orig_poc.html), relevant vulnerable code snippets, and explanation of the vulnerability are included. From here following the link to the respective [Chromium #952849](https://bugs.chromium.org/p/chromium/issues/detail?id=952849) issue provides us more detailed documentation of the [respective patch](https://chromium.googlesource.com/chromium/src.git/+/dfdade6af0418044402b3a6ffdc5c2ebbe7011d8%5E%21/) and the patched build version 75-3770.


Source code for respective vulnerable versions was retrieved as documented [here](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/linux/build_instructions.md) and [here](https://www.chromium.org/developers/how-tos/get-the-code/working-with-release-branches). To speed up development and ensure valid testing an official 71.0.3578.80 install was used rather than a custom build.



# Vulnerability Assesment
UAF vulnerabilities are categorized by their lifecycle of Retain -> Release -> Access. In Javascript we normally treat Release for identification as returning to user controlled javascrpt where we can further trigger code to perform the Release before an unchecked or poorly checked Access.

In this example the Retain, Release, and Access lifecycle is incredibly short and self-contained to a single function `AudioWorkletGlobalScope::Process()`. We have a Float32Array with a backing ArrayBuffer allocated and retained as a raw Vector pointer that we later perform a direct memcpy using. If we are able to release the backing ArrayBuffer we can replace the data on the heap with something more interesting. The snippets for each portion are contained and can be followed below.

**Retain:**
```c++
Vector<Vector<void*>> js_output_raw_ptrs;
js_output_raw_ptrs.ReserveInitialCapacity(output_buses->size());
for (auto* const output_bus : *output_buses) {
  js_output_raw_ptrs.UncheckedAppend(Vector<void*>());
  js_output_raw_ptrs.back().ReserveInitialCapacity(output_bus->NumberOfChannels());
  /* snip */
  for (uint32_t channel_index = 0; channel_index < output_bus->NumberOfChannels(); ++channel_index) {
    v8::Local<v8::ArrayBuffer> array_buffer = v8::ArrayBuffer::New(isolate, output_bus->length() * sizeof(float));
    v8::Local<v8::Float32Array> float32_array = v8::Float32Array::New(array_buffer, 0, output_bus->length());
    /* snip */
    const v8::ArrayBuffer::Contents& contents = array_buffer->GetContents();
    js_output_raw_ptrs.back().UncheckedAppend(contents.Data());
  }
}
```

**Release:**
```c++
AudioWorkletProcessorDefinition* definition = FindDefinition(processor->Name());
/* snip */
definition->ProcessFunction()->Invoke(processor,
  ScriptValue(script_state, inputs),
  ScriptValue(script_state, outputs),
  ScriptValue(script_state, param_values))
```

**Access:**
```c++
memcpy(output_bus->Channel(channel_index)->MutableData(),
             js_output_raw_ptrs[output_bus_index][channel_index],
             output_bus->length() * sizeof(float));
```



## Detaching the backing buffer
The `outputs` array received by our `AudioWorkletProcessor.process` function is a `v8::Buffer[number_of_channels]v8::Float32Array[bus_length * sizeof(float)]`. The saved reference and object we are trying to free for UAF is `Float32Array.buffer`. This can be accessed simply by `outputs[0][0].buffer`.

A *Float32Array* is a wrapper type around a *TypedArray* which is internally an `ArrayBufferView` with a backing `ArrayBuffer`. Normally the *buffer* js property is ReadOnly but through transferring the buffer via `port.postMessage` and including it in the transfer list you "detach" it from the TypeArray. The detaching is performed in `ArrayBuffer::Transfer` where itself and all Views are *Neutered* and detached before passing ownership of it's internal contexts to a copy.

```javascript
function process(inputs, outputs, params) {
  buffer = outputs[0][0].buffer
  try {
    this.port.postMessage([buffer], [buffer]);
  } catch {}
  return false;
}
```


## Heap isolate
Every Worker in V8 runs in it's own thread and has it's own V8 heap. This accomplishes a secondary and our primary goal when we detatch and transfer the `Float32Array.buffer`. Because of we are transferring across threads outside of the worklet the copied `ArrayBuffer` is subsequently free'd after transfer.

This is also why we transmit our *image_bitmap* data over the port to the worklet thread and context before calling `startRendering`. You can see this in practice in the source code at every allocation using `v8::Isolate`.


## Why is this bug a read-only UAF?
The bug manifests as a read-only UAF because of the dangling pointer held inside `js_output_raw_ptrs` is only used as a src argument inside of the memcpy after the call to the user controlled `ProcessFunction`.


# PoC Development
When working with a public bug or CVE using public knowledge is always a benefit to augment your own existing knowledge. I started with the provided [poc.html](poc.html) in the bug report from Sergei Glazunov of Project Zero.

This poc builds 2 canvas objects, one with a remote cross-domain image, and a second blank where we will output the recovered image. Initial observations of this PoC demonstrate recovery of the image with various artifacts and occasional missing data.

As part of my research I've taken the provided PoC and modified it to reliably recover a full copy of the original image. During my research I identified three primary issues:
- Corrupted pixel data
- Soft failures
- Lack of support for arbitrary image sizes

> **Original Recovered Image**
> 
> ![Original Recovered](orig_recovered.png)

> **Improved Recovered Image**
> 
> ![Improved Recovered](improved_recovered.png)


## Corrupted pixel data
After exploitaion the `audio_buffer.getChannelData(0)` returns a `Float32Array` copy of our image_data. We convert this immediatly to a `Uint8Array` necessary for creating a valid `ImageData` and repairing the byte order. The first 8 bytes of which are overwritten pixel data with a leaked 64-bit pointer. This reduces our available image data to 126 pixels at a time, from 512 bytes to 504 bytes. The initial poc recovered image data in a 16x8 rectangle with no regard to any missing or corrupted data. Because the first 2 pixels of the rectangle were corrupted and not simply offset it meant recovery would require overlapping and merging of image data.

To solve this problem I modified the recovered image rectangle to a 1x128 pixel vertical line. Allowing me to vertically offset the cross-domain image by -2 pixels and safely discard them after. After implementation I could full recovery 126 pixels at a time across the entire image.


## Soft failures
No heap grooming is performed as part of the PoC. This creates a high number of soft-failures where no valid image data is returned from the exploit. In order to solve this issue I added an identifier as the 1st valid pixel reducing the recovered image data to 125 pixels per attempt. A green line was choosen as the match requiring only a single draw call per each 125px vertical segment. Any failures are now easily identifiable and exploitation repeated until succesful. After implementation all recovered image data segments correctly had valid data.


## Arbitrary image sizes
When building the canvas and retrieving a corresponding ImageData buffer no checks are performed to ensure the source image dimensions were divisible by the original recovery rectangle size. This was added for the new recovery size of 125x1, with an additional 3 pixels of vertical height offset used for the above mentioned offset and soft-failure recovery.



# Discovery

## Manual identification

Manual auditing patterns to find this you'd look for raw pointer storage like straight Vectors `Vector<Vector<void*>>` or raw pointer access `array_buffer->GetContents().Data()`.

You can also look for comments such as the one included in this example:
> TODO(hongchan): Sanity check on length, number of channels, and object type.

New patches to the codebase during optimization can also be watched. Areas such as the audio rendering require high throughput and safety checks decrease their performance are areas of interest for manual auditing.


## Automation patterns

Automated identification statically requires first identifying javascript entry points and exit points.

Chromium implements EntryPoints via Web IDL format files to define javascript bindings. `OfflineAudioContext` is defined in *third_party/blink/renderer/modules/webaudio/offline_audio_context.idl*. We're calling `OfflineAudioContext.startRendering` which we can see actually maps to `OfflineAudioContext::startOfflineRendering`.

    [
      Constructor(unsigned long numberOfChannels, unsigned long numberOfFrames, float sampleRate),
      Constructor(OfflineAudioContextOptions options),
      ConstructorCallWith=ExecutionContext,
      RaisesException=Constructor,
      Measure
    ] interface OfflineAudioContext : BaseAudioContext {
      // Offline rendering
      attribute EventHandler oncomplete;
      readonly attribute unsigned long length;
      [CallWith=ScriptState, ImplementedAs=startOfflineRendering, MeasureAs=OfflineAudioContextStartRendering] Promise<AudioBuffer> startRendering();
      [CallWith=ScriptState, ImplementedAs=suspendContext, MeasureAs=OfflineAudioContextSuspend] Promise<void> suspend(double suspendTime);
      [MeasureAs=OfflineAudioContextResume, CallWith=ScriptState, ImplementedAs=resumeContext] Promise<void> resume();
    };



Identification of exit points is easier looking for functions such as `V8ScriptRunner::CallFunction` or `->Invoke` on a `v8::Function`.


---

With known entry points and exit points identified we now have to follow from start to all exits. The actual hard part lmao. In the past i've uplifted assembly into SSA and graphs to perform graph queries against. Working against a massive codebase like chromium makes any static analysis significantly more difficult.

Looking at the first issue you run into is proper call tracing of `DestinationHandler().StartRendering();`. `DestinationHandler()` returns `destination()->GetAudioDestinationHandler()` of which `destination()` is defined in the superclass `BaseAudioContext` where we find the access to `destination_node_`. Secondly `destination_node_` is initialized in the constructor function `OfflineAudioContext::OfflineAudioContext` with `destination_node_ = OfflineAudioDestinationNode::Create`. If you look purely at `AudioDestinationNode` or classes that inherit you incorrectly exclude valid classes or include invalid classes such as `RealtimeAudioDestinationNode`.



# Future research

* What address is leaked by the exploit and why is it written
* What other interesting data can be recovered
* Small visual artifacts near the edges of characters, most noticably around the yellow **O**
* Reduce failures and improve time with heap grooming/spraying and larger buffers