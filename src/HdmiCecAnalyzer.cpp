#include "HdmiCecAnalyzer.h"
#include "HdmiCecAnalyzerSettings.h"
#include <AnalyzerChannelData.h>

#include "HdmiCecProtocol.h"

HdmiCecAnalyzer::HdmiCecAnalyzer() : Analyzer2(), mSettings( new HdmiCecAnalyzerSettings() ), mSimulationInitilized( false )
{
    SetAnalyzerSettings( mSettings.get() );
}

HdmiCecAnalyzer::~HdmiCecAnalyzer()
{
    KillThread();
}

void HdmiCecAnalyzer::WorkerThread()
{
    mCec = GetAnalyzerChannelData( mSettings->mCecChannel );

    // For each successful iteration of this loop, we add a new packet and one or
    // more frames. A packet reperesents a "CEC frame" that may contain one or more
    // CEC blocks.
    while( true )
    {
        // Read the start sequence
        Frame startSeq;
        if( !ReadStartSequence( startSeq, false ) )
        {
            MarkErrorPosition();
            continue;
        }
        mResults->AddFrame( startSeq );
        mResults->CommitResults();
        ReportProgress( startSeq.mEndingSampleInclusive );

        int blockPosition = 0;
        bool eom = false;

        // Read all the 10-bit blocks in the message until the End of Message
        while( !eom )
        {
            // Block byte
            Frame byteFrame;
            if( !ReadBlockByte( blockPosition, byteFrame ) )
            {
                if( ReadStartSequence( startSeq, true ) )
                {
                    mResults->AddFrame( startSeq );
                    mResults->CommitResults();
                    ReportProgress( startSeq.mEndingSampleInclusive );

                    blockPosition = 0;
                    eom = false;
                    continue;
                }

                MarkErrorPosition();
                break;
            }
            mResults->AddFrame( byteFrame );
            mResults->CommitResults();
            ReportProgress( byteFrame.mEndingSampleInclusive );

            // Block End of Message bit
            Frame eomFrame;
            if( !ReadBlockEOM( eomFrame ) )
            {
                if( ReadStartSequence( startSeq, true ) )
                {
                    mResults->AddFrame( startSeq );
                    mResults->CommitResults();
                    ReportProgress( startSeq.mEndingSampleInclusive );

                    blockPosition = 0;
                    eom = false;
                    continue;
                }

                MarkErrorPosition();
                break;
            }
            mResults->AddFrame( eomFrame );
            mResults->CommitResults();
            ReportProgress( eomFrame.mEndingSampleInclusive );

            // Block ACK bit
            Frame ackFrame;
            if( !ReadBlockACK( ackFrame ) )
            {
                if( ReadStartSequence( startSeq, true ) )
                {
                    mResults->AddFrame( startSeq );
                    mResults->CommitResults();
                    ReportProgress( startSeq.mEndingSampleInclusive );

                    blockPosition = 0;
                    eom = false;
                    continue;
                }

                MarkErrorPosition();
                break;
            }
            mResults->AddFrame( ackFrame );
            mResults->CommitResults();
            ReportProgress( ackFrame.mEndingSampleInclusive );

            blockPosition++;
            eom = eomFrame.mData1;
        }

        // On the end of a successfully parsed message, insert an End marker
        // and commit the "packet"
        if( eom )
        {
            mResults->CommitPacketAndStartNewPacket();
            mResults->AddMarker( mCec->GetSampleNumber(), AnalyzerResults::Stop, mSettings->mCecChannel );
            mResults->CommitResults();
            ReportProgress( mCec->GetSampleNumber() );
        }
    }
}

bool HdmiCecAnalyzer::NeedsRerun()
{
    return false;
}

U32 HdmiCecAnalyzer::GenerateSimulationData( U64 minimum_sample_index, U32 device_sample_rate,
                                             SimulationChannelDescriptor** simulation_channels )
{
    if( mSimulationInitilized == false )
    {
        mSimulationDataGenerator.Initialize( GetSimulationSampleRate(), mSettings.get() );
        mSimulationInitilized = true;
    }

    return mSimulationDataGenerator.GenerateSimulationData( minimum_sample_index, device_sample_rate, simulation_channels );
}

U32 HdmiCecAnalyzer::GetMinimumSampleRateHz()
{
    return HdmiCec::MinSampleRateHz;
}

void HdmiCecAnalyzer::SetupResults()
{
    mResults.reset( new HdmiCecAnalyzerResults( this, mSettings.get() ) );
    SetAnalyzerResults( mResults.get() );
    mResults->AddChannelBubblesWillAppearOn( mSettings->mCecChannel );
}

const char* HdmiCecAnalyzer::GetAnalyzerName() const
{
    return HdmiCec::GetProtocolName();
}

const char* GetAnalyzerName()
{
    return HdmiCec::GetProtocolName();
}

Analyzer* CreateAnalyzer()
{
    return new HdmiCecAnalyzer();
}

void DestroyAnalyzer( Analyzer* analyzer )
{
    delete analyzer;
}

bool HdmiCecAnalyzer::ReadStartSequence( Frame& frame, bool at_start_of_sequence )
{
    // All timing values are taken from the CEC spec, section 5.2.1 "Start Bit Timing"

    if( !at_start_of_sequence )
    {
        // The bus should be in HIGH
        if( mCec->GetBitState() == BIT_LOW )
            mCec->AdvanceToNextEdge();

        // Advance to the next falling edge
        mCec->AdvanceToNextEdge(); // HIGH to LOW
    }

    frame.mType = HdmiCec::FrameType_StartSeq;
    frame.mData1 = 0;
    frame.mStartingSampleInclusive = mCec->GetSampleNumber();

    U32 samples_to_start_of_rising_edge_zone = double( GetSampleRate() ) * ( HdmiCec::Tim_Start_AMin / 1000.0 ); // convert ms to s
    U32 samples_to_end_of_rising_edge_zone = double( GetSampleRate() ) * ( HdmiCec::Tim_Start_AMax / 1000.0 );   // convert ms to s
    U32 samples_to_start_of_falling_edge_zone = double( GetSampleRate() ) * ( HdmiCec::Tim_Start_BMin / 1000.0 );
    U32 samples_to_end_of_falling_edge_zone = double( GetSampleRate() ) * ( HdmiCec::Tim_Start_BMax / 1000.0 );

    U32 transitions = 0;
    transitions = mCec->Advance( samples_to_start_of_rising_edge_zone );
    if( transitions > 0 ) // have to stay low during this time
        return false;

    transitions = mCec->Advance( samples_to_end_of_rising_edge_zone - samples_to_start_of_rising_edge_zone );
    if( ( transitions == 0 ) || ( mCec->GetBitState() == BIT_LOW ) ) // has to transition to HIGH in this time and end up HIGH
        return false;

    transitions = mCec->Advance( samples_to_start_of_falling_edge_zone - samples_to_end_of_rising_edge_zone );
    if( transitions > 0 ) // have to stay high during this time
        return false;


    // Need to snap to the last falling edge in the range of the falling edge

    mCec->AdvanceToNextEdge();
    float elapsed = TimeSince( frame.mStartingSampleInclusive );
    if( elapsed < HdmiCec::Tim_Start_BMin || elapsed > HdmiCec::Tim_Start_BMax )
        return false;

    // We now have a valid falling edge
    U32 current_samples_to_end = samples_to_end_of_falling_edge_zone - ( mCec->GetSampleNumber() - frame.mStartingSampleInclusive );
    while( mCec->WouldAdvancingCauseTransition( current_samples_to_end ) )
    {
        mCec->AdvanceToNextEdge();
        current_samples_to_end = samples_to_end_of_falling_edge_zone - ( mCec->GetSampleNumber() - frame.mStartingSampleInclusive );
    }

    if( mCec->GetBitState() == BIT_HIGH )
        return false;

    //// Advance until the end of the "a" pulse
    // mCec->AdvanceToNextEdge(); // LOW to HIGH
    // float elapsed = TimeSince( frame.mStartingSampleInclusive );

    //// Check that pulse ends in the correct time
    // if( elapsed < HdmiCec::Tim_Start_AMin || elapsed > HdmiCec::Tim_Start_AMax )
    //    return false;

    //// Advance until the end of the "b" pulse
    // mCec->AdvanceToNextEdge(); // HIGH to LOW
    // elapsed = TimeSince( frame.mStartingSampleInclusive );

    //// Check that the pulse ends in the correct time
    // if( elapsed < HdmiCec::Tim_Start_BMin || elapsed > HdmiCec::Tim_Start_BMax )
    //    return false;

    // Add start marker on beginning sequence
    mResults->AddMarker( frame.mStartingSampleInclusive, AnalyzerResults::Start, mSettings->mCecChannel );

    // The last sample is the sample just before the edge
    frame.mEndingSampleInclusive = mCec->GetSampleNumber() - 1;
    return true;
}

bool HdmiCecAnalyzer::ReadBlockByte( int blockIndex, Frame& byteFrame )
{
    // The bus should be in LOW
    if( mCec->GetBitState() == BIT_HIGH )
        mCec->AdvanceToNextEdge();

    // Read block byte
    bool value;
    U8 byte = 0;

    for( int bit = 7; bit >= 0; bit-- )
    {
        S64* firstSample = ( bit == 7 ) ? &byteFrame.mStartingSampleInclusive : 0;
        S64* lastSample = ( bit == 0 ) ? &byteFrame.mEndingSampleInclusive : 0;
        if( !ReadBit( value, firstSample, lastSample ) )
            return false;
        byte |= value << bit;
    }
    byteFrame.mData1 = byte;

    // Depending on the position on the message set blockByte type
    if( !blockIndex )
        byteFrame.mType = HdmiCec::FrameType_Header;
    else if( blockIndex == 1 )
        byteFrame.mType = HdmiCec::FrameType_OpCode;
    else if( blockIndex < HdmiCec::MaxMessageBlocks )
        byteFrame.mType = HdmiCec::FrameType_Operand;
    else
        return false;

    return true;
}

bool HdmiCecAnalyzer::ReadBlockEOM( Frame& eomFrame )
{
    bool eom;
    // Read EOM bit
    if( !ReadBit( eom, &eomFrame.mStartingSampleInclusive, &eomFrame.mEndingSampleInclusive ) )
        return false;
    eomFrame.mData1 = eom;
    eomFrame.mType = HdmiCec::FrameType_EOM;

    return true;
}

bool HdmiCecAnalyzer::ReadBlockACK( Frame& ackFrame )
{
    // The bus should be in LOW
    if( mCec->GetBitState() == BIT_HIGH )
        mCec->AdvanceToNextEdge();

    ackFrame.mStartingSampleInclusive = mCec->GetSampleNumber();

    S64 startSample = ackFrame.mStartingSampleInclusive;

    // Need to move to move to the safe sample period which is 1.05ms past the T0
    U32 samples_to_start_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 );   // convert ms to s
    U32 samples_to_nominal_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 ); // convert ms to s
    U32 samples_to_end_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 );     // convert ms to s
    U32 samples_to_safe_high_time =
        double( GetSampleRate() ) * ( ( HdmiCec::Tim_Bit_ZeroMax + ( HdmiCec::Tim_Bit_LenMin - HdmiCec::Tim_Bit_ZeroMax ) / 2.0 ) /
                                      1000.0 ); // the middle time between the last time to go high and before the first time to go low
    U32 samples_to_end_of_packet = double( GetSampleRate() ) * ( HdmiCec::Tim_Bit_LenMin / 1000.0 );
    U32 samples_to_middle_of_next_bit = double( GetSampleRate() ) * ( HdmiCec::Tim_Bit_Len / 1000.0 );

    U32 transitions = 0;
    bool ack = false;
    transitions = mCec->Advance( samples_to_start_sample_time );
    transitions = mCec->Advance( samples_to_nominal_sample_time - samples_to_start_sample_time );
    if( transitions > 0 )
        return false;

    if( mCec->GetBitState() == BIT_LOW )
        ack = true;

    transitions = mCec->Advance( samples_to_end_sample_time - samples_to_nominal_sample_time );
    if( transitions > 0 )
        return false;

    // Mark ACK bit
    mResults->AddMarker( mCec->GetSampleNumber(), ack ? AnalyzerResults::One : AnalyzerResults::Zero, mSettings->mCecChannel );

    mCec->Advance( samples_to_safe_high_time - samples_to_end_sample_time );


    U64 start_of_transition_zone = samples_to_end_of_packet - samples_to_safe_high_time;
    U64 middle_of_transition_zone = samples_to_middle_of_next_bit - samples_to_safe_high_time;

    if( mCec->WouldAdvancingCauseTransition( start_of_transition_zone ) )
        return false;
    //// If by the nominal data bit period there is no rising edge, move there,
    //// else move to the minimum data bit period
    if( mCec->WouldAdvancingCauseTransition( middle_of_transition_zone ) )
        mCec->Advance( start_of_transition_zone );
    else
        mCec->Advance( middle_of_transition_zone );

    // Old code that did not respect the valid sample range
    // mCec->AdvanceToNextEdge(); // LOW to HIGH
    // float elapsed = TimeSince( ackFrame.mStartingSampleInclusive );

    //// Logic values are inverted for ACK
    // bool ack = elapsed > HdmiCec::Tim_Bit_ZeroMin && elapsed < HdmiCec::Tim_Bit_ZeroMax;
    //// Ack rising edge should happen before the earliest time for the start of the next bit
    // if( elapsed >= HdmiCec::Tim_Bit_LenMin )
    //    return false;

    //// Mark ACK bit
    // mResults->AddMarker( mCec->GetSampleNumber(), ack ? AnalyzerResults::One : AnalyzerResults::Zero,
    //                     mSettings->mCecChannel );

    //// Advance to the end of the data bit
    //// The bus should stay in HIGH at least until HdmiCec::Tim_Bit_LenMin
    // U32 samplesToAdvance1 = ( HdmiCec::Tim_Bit_LenMin - elapsed ) * GetSampleRate() / 1000.0;
    // if( mCec->WouldAdvancingCauseTransition( samplesToAdvance1 ) )
    //    return false;
    ////// If by the nominal data bit period there is no rising edge, move there,
    ////// else move to the minimum data bit period
    // U32 samplesToAdvance2 = ( HdmiCec::Tim_Bit_Len - elapsed ) * GetSampleRate() / 1000.0;
    // if( mCec->WouldAdvancingCauseTransition( samplesToAdvance2 ) )
    //    mCec->Advance( samplesToAdvance1 );
    // else
    //    mCec->Advance( samplesToAdvance2 );

    ackFrame.mData1 = ack;
    ackFrame.mType = HdmiCec::FrameType_ACK;
    ackFrame.mEndingSampleInclusive = mCec->GetSampleNumber() - 1;

    return true;
}

bool HdmiCecAnalyzer::ReadBit( bool& value, S64* firstSample, S64* lastSample )
{
    // All timing values are taken from the CEC spec, section 5.2.2 "Data Bit Timing"

    // The bus should be in LOW
    if( mCec->GetBitState() == BIT_HIGH )
        mCec->AdvanceToNextEdge();

    S64 startSample = mCec->GetSampleNumber();

    // Need to move to move to the safe sample period which is 1.05ms past the T0
    U32 samples_to_start_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 );   // convert ms to s
    U32 samples_to_nominal_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 ); // convert ms to s
    U32 samples_to_end_sample_time = double( GetSampleRate() ) * ( HdmiCec::Tim_Sample_Time_Start / 1000.0 );     // convert ms to s
    U32 samples_to_safe_high_time =
        double( GetSampleRate() ) * ( ( HdmiCec::Tim_Bit_ZeroMax + ( HdmiCec::Tim_Bit_LenMin - HdmiCec::Tim_Bit_ZeroMax ) / 2.0 ) /
                                      1000.0 ); // the middle time between the last time to go high and before the first time to go low

    S32 transitions = 0;
    transitions = mCec->WouldAdvancingCauseTransition( samples_to_safe_high_time );
    if( transitions == 0 ) // this will allow us to catch if we are in a start bit without advancing the iterator
        return false;

    transitions = mCec->Advance( samples_to_start_sample_time );
    // don't care about the number of transitions to the start of the sample time
    transitions = mCec->Advance( samples_to_nominal_sample_time - samples_to_start_sample_time );
    if( transitions > 0 ) // in the valid sample time range there should be no transitions
        return false;

    // We should now sample the line
    if( mCec->GetBitState() == BIT_HIGH )
        value = true;
    else
        value = false;

    transitions = mCec->Advance( samples_to_end_sample_time - samples_to_nominal_sample_time );
    if( transitions > 0 ) // in the valid sample time range there should be no transitions
        return false;

    // Mark bit
    mResults->AddMarker( mCec->GetSampleNumber(), value ? AnalyzerResults::One : AnalyzerResults::Zero, mSettings->mCecChannel );

    mCec->Advance( samples_to_safe_high_time - samples_to_end_sample_time );

    if( mCec->GetBitState() == BIT_LOW ) // The Line should be high by now
        return false;

    mCec->AdvanceToNextEdge(); // HIGH to LOW
    float elapsed = TimeSince( startSample );
    // Check overall bit period
    if( elapsed < HdmiCec::Tim_Bit_LenMin || elapsed > HdmiCec::Tim_Bit_LenMax )
        return false;

    if( firstSample )
        *firstSample = startSample;
    if( lastSample )
        *lastSample = mCec->GetSampleNumber() - 1;

    return true;
}

float HdmiCecAnalyzer::TimeSince( S64 sample )
{
    const S64 sampleDiff = mCec->GetSampleNumber() - sample;
    return sampleDiff * 1000.0 / GetSampleRate();
}

void HdmiCecAnalyzer::MarkErrorPosition()
{
    mResults->AddMarker( mCec->GetSampleNumber(), AnalyzerResults::ErrorDot, mSettings->mCecChannel );
    mResults->CommitResults();
    ReportProgress( mCec->GetSampleNumber() );
    // On error, cancel the packet and look for another start sequence
    mResults->CancelPacketAndStartNewPacket();
}
